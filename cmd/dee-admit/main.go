// Command dee-admit issues the credentials a relay admits: mint, renew, revoke,
// list.
//
// It is a separate binary from the relay, and that is a decision rather than a
// packaging accident. The relay must never branch on a tier label — that is what
// keeps a price list out of an Apache-2.0 binary and stops a self-hoster
// inheriting a commercial vocabulary — and an issuance tool's whole job is to
// turn a tier label into numbers. It is also the one thing in this module that
// writes to disk, which the relay's durable-state audit forbids.
//
// It runs on the box that holds the credential file, as whoever may write it,
// and it is not a service: nothing here listens, nothing here is scheduled, and
// the credential file is the only thing it touches.
//
//	dee-admit mint   --tier crew --days 14
//	dee-admit renew  --code A1B2… --days 30
//	dee-admit revoke --credential <id>
//	dee-admit list
//
// The relay re-reads the file on SIGHUP; every command that changes it says so
// on the way out. Restarting instead would empty every other circle's queue.
//
// One command breaks the "writes to disk, talks to nobody" description above:
//
//	dee-admit session --code - --relay https://relay.example.org
//
// It touches no file and opens a real admission session against a running
// relay, so that deploy/setup-verify.sh can put a canary through a closed gate
// and so an operator can see the actual refusal behind "my code does not work".
// It lives here because the code → keypair derivation does, and a second
// implementation of it in a shell script is the one that drifts. See session.go.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"deechat/chat-node/internal/admission"
	"deechat/chat-node/internal/issue"
)

const usage = `dee-admit — issue the credentials a relay admits.

  dee-admit mint   [--tier <name>] --days <n> [--file <path>] [--tiers <path>]
  dee-admit renew  (--code <code> | --credential <id>) --days <n> [--file <path>]
  dee-admit revoke (--code <code> | --credential <id>) [--file <path>]
  dee-admit list   [--file <path>]
  dee-admit session (--code <code> | --code -) --relay <url> [--verbose]

The credential file defaults to $DEE_NODE_ADMISSION_FILE — the same one the relay
reads. The tier presets default to $DEE_ADMIT_TIERS, and are only consulted when
--tier names one; without a tier the credential grants the box's own caps and is
a gate, not a product.

--code accepts "-" to read the code from standard input, which keeps it out of
the shell history and out of the process list.

session touches no file. It opens a real admission session against a running
relay and prints the token on stdout, so a verification run can carry it as
X-Dee-Admission and an operator can see why a code is being refused.

A minted code is shown once. Nothing stores it, here or on the relay, and it
cannot be recovered from anything that is stored — renewal extends the window on
the same code, so a customer who has it never needs a new one.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "mint":
		err = mint(os.Args[2:])
	case "renew":
		err = renew(os.Args[2:])
	case "revoke":
		err = revoke(os.Args[2:])
	case "list":
		err = list(os.Args[2:])
	case "session":
		err = session(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "dee-admit: %v\n", err)
		os.Exit(1)
	}
}

// flags is the set every subcommand shares. The credential file is on all four
// because issuing against the wrong file is the mistake with no symptom: the
// mint succeeds, the code is handed over, and the relay admitting nobody new is
// discovered by the customer.
type flags struct {
	set        *flag.FlagSet
	file       string
	tiers      string
	tier       string
	days       int
	code       string
	credential string
}

func newFlags(name string) *flags {
	set := flag.NewFlagSet(name, flag.ExitOnError)
	f := &flags{set: set}
	set.StringVar(&f.file, "file", os.Getenv("DEE_NODE_ADMISSION_FILE"), "credential file the relay reads")
	set.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	return f
}

func (f *flags) withTier() *flags {
	f.set.StringVar(&f.tiers, "tiers", os.Getenv("DEE_ADMIT_TIERS"), "tier presets file (deploy/tiers.example.json)")
	f.set.StringVar(&f.tier, "tier", "", "tier to grant; omit for a credential that grants the box's own caps")
	return f
}

func (f *flags) withDays() *flags {
	f.set.IntVar(&f.days, "days", 0, "length of the window in days")
	return f
}

func (f *flags) withSubject() *flags {
	f.set.StringVar(&f.code, "code", "", `the customer's redemption code, or "-" to read it from stdin`)
	f.set.StringVar(&f.credential, "credential", "", "the credential id, as printed by mint or list")
	return f
}

// subject resolves which credential a command names. Either the id — which the
// operator has from mint or list — or the code, which is what the customer has
// and what a support thread quotes. Deriving the id from the code is one-way, so
// taking one costs nothing that is stored.
func (f *flags) subject() (string, error) {
	switch {
	case f.credential != "" && f.code != "":
		return "", errors.New("give --code or --credential, not both")
	case f.credential != "":
		return f.credential, nil
	case f.code == "":
		return "", errors.New("name a credential: --credential <id>, or --code <the customer's code>")
	}
	code := f.code
	if code == "-" {
		read, err := issue.ReadCode(os.Stdin)
		if err != nil {
			return "", err
		}
		code = read
	}
	return issue.CredentialFromCode(code)
}

func (f *flags) window() (time.Duration, error) {
	if f.days <= 0 {
		return 0, errors.New("--days must be a positive number of days: expiry is the enforcement model, and a credential without a window is a permanent free hosted tier")
	}
	return time.Duration(f.days) * 24 * time.Hour, nil
}

func mint(args []string) error {
	f := newFlags("mint").withTier().withDays()
	_ = f.set.Parse(args)
	window, err := f.window()
	if err != nil {
		return err
	}

	terms := admission.Terms{}
	if f.tier != "" {
		if f.tiers == "" {
			return errors.New("--tier needs a presets file: pass --tiers, or set DEE_ADMIT_TIERS (deploy/tiers.example.json is the one we ship)")
		}
		presets, err := issue.LoadPresets(f.tiers)
		if err != nil {
			return err
		}
		preset, err := presets.Lookup(f.tier)
		if err != nil {
			return err
		}
		terms = preset.Terms(time.Now().Add(window))
	} else {
		terms.NotAfter = time.Now().Add(window).UTC().Truncate(time.Second)
	}

	file, err := issue.Open(f.file)
	if err != nil {
		return err
	}
	code, credential, err := file.Mint(terms)
	if err != nil {
		return err
	}
	if err := file.Save(); err != nil {
		return err
	}

	// The code first and alone, because this is the only moment it exists.
	fmt.Printf("code        %s\n", code)
	fmt.Printf("            Give this to the steward. It is not stored anywhere and cannot be re-read.\n\n")
	printCredential(credential, time.Now())
	fmt.Printf("file        %s (%d credential%s)\n", file.Path(), file.Count(), plural(file.Count()))
	printReloadHint(file)
	return nil
}

func renew(args []string) error {
	f := newFlags("renew").withSubject().withDays()
	_ = f.set.Parse(args)
	id, err := f.subject()
	if err != nil {
		return err
	}
	window, err := f.window()
	if err != nil {
		return err
	}

	file, err := issue.Open(f.file)
	if err != nil {
		return err
	}
	now := time.Now()
	was, is, err := file.Renew(id, now, window)
	if err != nil {
		return explainMissing(err, id)
	}
	if err := file.Save(); err != nil {
		return err
	}

	fmt.Printf("credential  %s\n", id)
	fmt.Printf("was         %s (%s)\n", was.UTC().Format(time.RFC3339), remaining(was, now))
	fmt.Printf("notAfter    %s (%s)\n", is.UTC().Format(time.RFC3339), remaining(is, now))
	if was.Before(now) {
		// Worth saying rather than leaving to arithmetic: a lapsed circle's
		// window runs from today, so the days it was expired are not credited
		// back and the operator can see that before the customer does.
		fmt.Printf("            The window had already ended, so the renewal runs from now.\n")
	}
	fmt.Printf("code        unchanged — renewal never mints a new one, and no member re-provisions\n")
	fmt.Printf("file        %s (%d credential%s)\n", file.Path(), file.Count(), plural(file.Count()))
	printReloadHint(file)
	return nil
}

func revoke(args []string) error {
	f := newFlags("revoke").withSubject()
	_ = f.set.Parse(args)
	id, err := f.subject()
	if err != nil {
		return err
	}

	file, err := issue.Open(f.file)
	if err != nil {
		return err
	}
	revoked, err := file.Revoke(id)
	if err != nil {
		return explainMissing(err, id)
	}
	if err := file.Save(); err != nil {
		return err
	}

	fmt.Printf("revoked     %s", id)
	if revoked.Terms.Tier != "" {
		fmt.Printf("  (%s)", revoked.Terms.Tier)
	}
	fmt.Printf("\nfile        %s (%d credential%s)\n", file.Path(), file.Count(), plural(file.Count()))
	if file.Count() == 0 {
		// An enforcing relay refuses a reload that would load zero credentials,
		// so the operator has to know now that this file no longer reloads —
		// the alternative is a signal that appears to do nothing.
		fmt.Printf("\n            This file now admits nobody. An enforcing relay REFUSES a reload\n")
		fmt.Printf("            that would empty its credential set, so the running relay keeps the\n")
		fmt.Printf("            set it has until it is restarted — which drops every queue on it.\n")
		return nil
	}
	printReloadHint(file)
	return nil
}

func list(args []string) error {
	f := newFlags("list")
	_ = f.set.Parse(args)
	file, err := issue.Open(f.file)
	if err != nil {
		return err
	}
	credentials := file.Credentials()
	if len(credentials) == 0 {
		// The two empties are worth telling apart: a file that is not there is
		// usually the wrong path, and a file that is there and empty is a relay
		// that admits nobody.
		if !file.Existed() {
			fmt.Printf("%s does not exist yet — no credential has been minted into it.\n", file.Path())
			return nil
		}
		fmt.Printf("%s admits nobody.\n", file.Path())
		return nil
	}
	now := time.Now()
	fmt.Printf("%-44s  %-10s  %-20s  %s\n", "CREDENTIAL", "TIER", "NOTAFTER", "")
	for _, credential := range credentials {
		tier := credential.Terms.Tier
		if tier == "" {
			tier = "—"
		}
		fmt.Printf("%-44s  %-10s  %-20s  %s\n",
			credential.ID, tier,
			credential.Terms.NotAfter.UTC().Format(time.RFC3339),
			remaining(credential.Terms.NotAfter, now))
	}
	fmt.Printf("\n%d credential%s in %s\n", len(credentials), plural(len(credentials)), file.Path())
	return nil
}

func printCredential(credential admission.Credential, now time.Time) {
	fmt.Printf("credential  %s\n", credential.ID)
	if credential.Terms.Tier != "" {
		fmt.Printf("tier        %s\n", credential.Terms.Tier)
	} else {
		fmt.Printf("tier        (none) — this credential gates the relay and grants its box caps\n")
	}
	fmt.Printf("notAfter    %s (%s)\n", credential.Terms.NotAfter.UTC().Format(time.RFC3339), remaining(credential.Terms.NotAfter, now))
	fmt.Printf("terms       %s\n", describe(credential.Terms))
}

// describe renders the granted terms the way the relay reads them: a zero is not
// "unlimited", it is "whatever this box allows", and the difference matters when
// an operator is checking why a circle got more than the tier says.
func describe(terms admission.Terms) string {
	parts := []string{
		field("queueSlots", terms.QueueSlots != 0, fmt.Sprintf("%d", terms.QueueSlots)),
		field("retention", terms.RetentionWindow != 0, terms.RetentionWindow.String()),
		field("attachment", terms.AttachmentBytes != 0, humanBytes(int64(terms.AttachmentBytes))),
		field("transfers", terms.ConcurrentTransfers != 0, fmt.Sprintf("%d", terms.ConcurrentTransfers)),
		field("transit", terms.TransitBytesPerDay != 0, humanBytes(terms.TransitBytesPerDay)+"/24h"),
		field("perPair", terms.MaxPerPair != 0, fmt.Sprintf("%d", terms.MaxPerPair)),
	}
	return strings.Join(parts, " · ")
}

func field(name string, set bool, value string) string {
	if !set {
		return name + " box"
	}
	return name + " " + value
}

func humanBytes(value int64) string {
	switch {
	case value >= 1<<30:
		return fmt.Sprintf("%.4g GB", float64(value)/(1<<30))
	case value >= 1<<20:
		return fmt.Sprintf("%.4g MB", float64(value)/(1<<20))
	default:
		return fmt.Sprintf("%d B", value)
	}
}

func remaining(notAfter, now time.Time) string {
	if !notAfter.After(now) {
		return "EXPIRED"
	}
	// Rounded, not truncated: a window minted a second ago for 14 days has 13
	// days and 23 hours left, and printing "13 days" beside a 14-day sale is the
	// kind of small wrongness that costs a support thread.
	days := int((notAfter.Sub(now) + 12*time.Hour).Hours() / 24)
	if days < 1 {
		return "under a day left"
	}
	return fmt.Sprintf("%d day%s left", days, plural(days))
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// explainMissing says the useful thing when a credential is not in the file. The
// two ways to get here are a typo and the wrong file, and the second one is the
// expensive one — a box with more than one relay's credentials on it, or a
// $DEE_NODE_ADMISSION_FILE that is not the one this relay reads.
func explainMissing(err error, id string) error {
	if errors.Is(err, issue.ErrNoSuchCredential) {
		return fmt.Errorf("%w: %s. Check the credential file is the one this relay reads, and that the code was typed as the customer has it", err, id)
	}
	return err
}

// printReloadHint names the step that makes the edit real. Every command that
// writes ends here, because a credential file the relay has not re-read is a
// mint that appears to have worked.
func printReloadHint(file *issue.File) {
	fmt.Printf("\nnext        systemctl kill -s HUP %s\n", unitName())
	fmt.Printf("            The relay re-reads %s. Do not restart it — the queues are\n", filepath.Base(file.Path()))
	fmt.Printf("            RAM-only, so a restart drops every other circle's undelivered mail.\n")
}

func unitName() string {
	if name := os.Getenv("DEE_ADMIT_UNIT"); name != "" {
		return name
	}
	return "dee-relay"
}
