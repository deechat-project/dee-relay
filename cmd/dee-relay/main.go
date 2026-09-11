package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"deechat/chat-node/internal/admission"
	"deechat/chat-node/internal/attachment"
	"deechat/chat-node/internal/config"
	"deechat/chat-node/internal/httpapi"
	"deechat/chat-node/internal/mesh"
	"deechat/chat-node/internal/peer"
	"deechat/chat-node/internal/prekey"
	"deechat/chat-node/internal/presence"
	"deechat/chat-node/internal/queue"
)

func main() {
	cfg := config.FromEnv()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Refusing to boot is the point. Every rule in Validate exists because an
	// earlier build accepted the misconfiguration, logged a warning into a
	// volatile journal, and ran — and for the mesh ones the result was a pool that
	// reported meshEnabled=true and replicated nothing.
	if errs := cfg.Validate(); len(errs) > 0 {
		for _, err := range errs {
			logger.Error("invalid configuration", "error", err)
		}
		os.Exit(2)
	}

	store := queue.NewStore(queue.StoreConfig{
		MaxMessages:     cfg.MaxMessages,
		MaxAcks:         cfg.MaxAcks,
		MaxPurges:       cfg.MaxPurges,
		MaxPerPair:      cfg.MaxPerPair,
		MaxPayloadBytes: cfg.MaxPayloadBytes,
		MaxTTL:          cfg.MaxTTL,
		DefaultTTL:      cfg.DefaultTTL,
		Now:             time.Now,
	})
	pool := peer.NewPool(cfg.NodeID, cfg.PublicURL, cfg.MeshPeers)
	// A moved node is otherwise invisible: it keeps answering on 0.0.0.0, so
	// nothing an operator polls says that the address every peer routes to has
	// stopped being this box.
	pool.OnSelfURLChange(func(previous, current string) {
		logger.Warn("advertised public url re-derived: this host's address changed",
			"previous", previous, "current", current, "configured", cfg.PublicURL)
	})
	presenceStore := presence.NewStore(5000, 24*time.Hour, time.Now)
	attachmentStore := attachment.NewRelay(cfg.RelayMaxWindow, cfg.MaxChunkBytes, cfg.MaxAttachmentBytes, cfg.RelayMaxSessions, cfg.RelayIdleTimeout, time.Now)
	// One-time prekeys are pinned to this home node (claim-once authority) and
	// are deliberately NOT mesh-replicated — the syncer never carries them.
	// Sized from cfg, not from the package defaults: this store replaces the one
	// NewServer builds, so anything it does not carry is a configured cap the
	// deployed relay silently does not have.
	prekeyStore := prekey.NewStoreWithLimits(httpapi.PrekeyLimits(cfg), time.Now)

	// Which circles this box carries mail for. An empty store is an open box —
	// the free self-hosted path — so the enforcing case is checked separately
	// and refuses the boot.
	admissions := admission.NewStore()
	if cfg.AdmissionFile != "" {
		loaded, err := admissions.LoadFile(cfg.AdmissionFile)
		if err != nil {
			logger.Error("admission credentials", "file", cfg.AdmissionFile, "error", err)
			os.Exit(2)
		}
		logger.Info("admission credentials loaded", "file", cfg.AdmissionFile, "credentials", loaded)
	}
	if cfg.RequireAdmission && admissions.Count() == 0 {
		logger.Error("invalid configuration", "error",
			"DEE_NODE_REQUIRE_ADMISSION is on and no credentials loaded: this relay would refuse every circle")
		os.Exit(2)
	}

	server := httpapi.NewServerWithStores(cfg, store, pool, presenceStore, attachmentStore, prekeyStore).
		WithAdmissions(admissions)
	syncer := mesh.NewSyncer(cfg, store, pool, presenceStore)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SIGHUP re-reads the credential file, and it exists because the alternative
	// is worse than it sounds: this relay's queues are RAM-only, so restarting to
	// revoke one circle's credential drops every other circle's undelivered mail.
	// A bad file leaves the previous set in place — a reload that half-applies is
	// a relay that has stopped admitting circles the operator believes it admits.
	if cfg.AdmissionFile != "" {
		hangup := make(chan os.Signal, 1)
		signal.Notify(hangup, syscall.SIGHUP)
		go func() {
			for {
				select {
				case <-hangup:
					// Read, inspect, then apply — never apply and then discover.
					reloaded, err := admission.ReadFile(cfg.AdmissionFile)
					if err != nil {
						logger.Error("admission reload failed; keeping the credentials already loaded",
							"file", cfg.AdmissionFile, "error", err)
						continue
					}
					if cfg.RequireAdmission && len(reloaded) == 0 {
						// Refused rather than applied: an enforcing relay that
						// reloads an empty file would stop serving every circle
						// at once, which is not a state anyone reaches on purpose.
						logger.Error("admission reload refused: the file holds zero credentials and this relay is enforcing",
							"file", cfg.AdmissionFile)
						continue
					}
					admissions.Replace(reloaded)
					logger.Info("admission credentials reloaded", "credentials", len(reloaded))
				case <-ctx.Done():
					signal.Stop(hangup)
					return
				}
			}
		}()
	}

	go func() {
		ticker := time.NewTicker(cfg.CleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				pool.RefreshSelfURL()
				store.PruneExpired(time.Now())
				presenceStore.Prune()
				attachmentStore.Prune()
				prekeyStore.Prune()
			case <-ctx.Done():
				return
			}
		}
	}()

	if len(cfg.MeshPeers) > 0 && cfg.MeshEnabled() && cfg.MeshSyncInterval > 0 {
		go func() {
			ticker := time.NewTicker(cfg.MeshSyncInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					// A failure here is logged, and the journal is volatile — so the
					// durable signal is the mesh block on /health, which monitor.sh
					// asserts. A log line nobody reads is how a pool replicates
					// nothing for an hour while looking healthy.
					for _, err := range syncer.SyncAll(ctx) {
						logger.Warn("mesh sync failed", "error", err)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           server.Handler(),
		ErrorLog:          serverErrorLog(logger),
		ReadHeaderTimeout: 5 * time.Second,
		// Body reads are bounded per request inside the handler chain (see
		// httpapi.limitBodies) rather than by Server.ReadTimeout, which would
		// also cut the long-poll on GET /attachments/chunks. IdleTimeout is the
		// other half: without it a kept-alive connection a client leaked — an
		// abandoned request whose socket is never closed — is held until the
		// process restarts, which is how one relay ended a session holding 28 of
		// them.
		IdleTimeout: cfg.IdleTimeout,
	}

	// The mesh listener is a second server on a private address, because /mesh/*
	// is not mounted on the public one in any configuration. Config validation has
	// already refused a wildcard or public bind here.
	var meshServer *http.Server
	if handler := server.MeshHandler(); handler != nil && cfg.MeshAddr != "" {
		meshServer = &http.Server{
			Addr:              cfg.MeshAddr,
			Handler:           handler,
			ErrorLog:          serverErrorLog(logger),
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       cfg.IdleTimeout,
		}
		go func() {
			logger.Info("mesh listener", "addr", cfg.MeshAddr, "peers", len(cfg.MeshPeers))
			if err := meshServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				// Fatal on purpose: a relay whose mesh listener is not up is a relay
				// the rest of the pool cannot replicate from, and it would otherwise
				// keep serving clients while quietly dropping out of the pool.
				logger.Error("mesh listener failed", "error", err)
				os.Exit(1)
			}
		}()
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if meshServer != nil {
			if err := meshServer.Shutdown(shutdownCtx); err != nil {
				logger.Error("mesh listener shutdown failed", "error", err)
			}
		}
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("server shutdown failed", "error", err)
		}
	}()

	logger.Info("dee relay listening", "addr", cfg.Addr, "node_id", cfg.NodeID)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}
