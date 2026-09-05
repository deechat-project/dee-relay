package main

// The `session` subcommand is the odd one out in this binary: every other
// command edits the credential file, and this one touches no file at all. It is
// here rather than in a script for one reason — the derivation.
//
// A redemption code becomes a keypair through
// SHA-256("deechat.admission-key.v1|" + normalized code) → Ed25519 seed → sign.
// Three sides already implement exactly that: the relay (internal/admission),
// the DeeChat client, and this binary.
// A fourth implementation stitched out of `openssl dgst` and `openssl pkeyutl`
// in a bash script would be the one nobody runs the unit tests over, and the
// first thing to drift when the domain string is versioned. So the script that
// needs a session asks the binary that already knows how, and gets a token back.
//
// What it is for: deploy/setup-verify.sh, run on a relay whose gate is closed.
// Without a session the verifier's canary is refused 401 and the whole delivery
// half of the report — accepted, read back, withheld without the secret, drained
// by the ack, swept afterwards — cannot run on the one kind of box that is
// actually carrying paid mail.
//
// It is deliberately usable by hand too. An operator debugging "the customer
// says their code does not work" runs this against the relay and gets the real
// refusal, told apart: expired window, not on this box, or a mistyped code.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"deechat/chat-node/internal/admission"
	"deechat/chat-node/internal/issue"
)

// sessionTimeout bounds the two calls. A relay that has not answered a challenge
// in this long is not a relay a verification run should keep waiting on — the
// script has its own report to finish.
const sessionTimeout = 20 * time.Second

func session(args []string) error {
	f := newFlags("session").withSubject()
	var relay string
	var verbose bool
	f.set.StringVar(&relay, "relay", "", "the relay to open a session against, e.g. https://relay.example.org")
	f.set.BoolVar(&verbose, "verbose", false, "print the granted terms to stderr as well")
	_ = f.set.Parse(args)

	if relay == "" {
		return errors.New("--relay is required: this command talks to a running relay, it does not read the credential file")
	}
	relay = strings.TrimRight(relay, "/")

	// The code, not the credential id: a session needs the private half, and only
	// the code carries it. --credential names a credential for the file-editing
	// commands and cannot produce a signature, so it is refused here rather than
	// failing later with a signature that was never possible.
	if f.credential != "" && f.code == "" {
		return errors.New("a session needs the code itself, not the credential id: only the code derives the key that signs the challenge")
	}
	code := f.code
	if code == "" {
		return errors.New(`name the code: --code <the customer's code>, or --code - to read it from stdin`)
	}
	if code == "-" {
		read, err := issue.ReadCode(os.Stdin)
		if err != nil {
			return err
		}
		code = read
	}
	if admission.NormalizeCode(code) == "" {
		return errors.New("that is not a redemption code")
	}
	key, credentialID := admission.KeyFromCode(code)

	client := &http.Client{Timeout: sessionTimeout}

	nonce, err := challenge(client, relay)
	if err != nil {
		return err
	}

	signature := signChallenge(key, nonce, credentialID)

	token, expiresIn, terms, err := redeem(client, relay, credentialID, nonce, signature)
	if err != nil {
		return err
	}

	// The token alone on stdout, everything else on stderr. This is the one
	// command in the binary whose output is consumed by another program —
	// `token="$(dee-admit session --code - --relay "$url")"` has to work without
	// a parser, and a human running it still sees the detail.
	fmt.Println(token)
	fmt.Fprintf(os.Stderr, "credential  %s\n", credentialID)
	fmt.Fprintf(os.Stderr, "session     valid for %ds — present it as X-Dee-Admission on every request\n", expiresIn)
	if verbose {
		fmt.Fprintf(os.Stderr, "terms       %s\n", describeGrantedTerms(terms))
	}
	return nil
}

// signChallenge is the derivation this whole command exists to keep in one
// place: the transcript is built by internal/admission, signed with the key the
// code derives, and encoded the way the relay decodes it.
func signChallenge(key ed25519.PrivateKey, nonce, credentialID string) string {
	return base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(key, admission.Transcript(nonce, credentialID)))
}

func challenge(client *http.Client, relay string) (string, error) {
	body, status, err := call(client, relay+"/admission/challenge", nil)
	if err != nil {
		return "", fmt.Errorf("POST %s/admission/challenge: %w", relay, err)
	}
	switch status {
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return "", errors.New("the relay has too many outstanding challenges; retry shortly")
	case http.StatusNotFound:
		return "", fmt.Errorf("%s has no /admission/challenge — it is running a build from before the gate, and cannot admit anyone", relay)
	default:
		return "", fmt.Errorf("POST %s/admission/challenge returned %d: %s", relay, status, explain(body))
	}
	var value struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(body, &value); err != nil || value.Nonce == "" {
		return "", fmt.Errorf("%s answered the challenge with something that is not a nonce — is that URL the relay, or a proxy in front of it?", relay)
	}
	return value.Nonce, nil
}

func redeem(client *http.Client, relay, credentialID, nonce, signature string) (string, int, map[string]any, error) {
	request, err := json.Marshal(map[string]string{
		"credential": credentialID,
		"nonce":      nonce,
		"signature":  signature,
	})
	if err != nil {
		return "", 0, nil, err
	}
	body, status, err := call(client, relay+"/admission/redeem", request)
	if err != nil {
		return "", 0, nil, fmt.Errorf("POST %s/admission/redeem: %w", relay, err)
	}

	// The three refusals are one status code and three different jobs for
	// whoever is reading. The relay gives one answer to a caller with no proof
	// on purpose (it must not be an oracle for which circles buy from us), but
	// this caller HAS proved the code, so the distinction it does draw —
	// expired versus not admitted — is the whole value of running this by hand.
	if status != http.StatusOK {
		switch failureCode(body) {
		case "admission_expired":
			return "", 0, nil, fmt.Errorf("this code's window has ended on %s. Renew it: dee-admit renew --code - --days <n>, then SIGHUP the relay", relay)
		case "admission_refused":
			return "", 0, nil, fmt.Errorf("%s does not admit this code. Either it was minted into a different relay's credential file, or it was revoked, or a character was mistyped — the credential id it derives is %s, and `dee-admit list` on that box says whether the relay has it", relay, credentialID)
		case "admission_busy":
			return "", 0, nil, errors.New("the relay is holding too many live sessions; retry shortly")
		default:
			return "", 0, nil, fmt.Errorf("POST %s/admission/redeem returned %d: %s", relay, status, explain(body))
		}
	}

	var value struct {
		Session      string         `json:"session"`
		ExpiresInSec int            `json:"expiresInSec"`
		Terms        map[string]any `json:"terms"`
	}
	if err := json.Unmarshal(body, &value); err != nil || value.Session == "" {
		return "", 0, nil, fmt.Errorf("%s accepted the proof but returned no session token", relay)
	}
	return value.Session, value.ExpiresInSec, value.Terms, nil
}

func call(client *http.Client, url string, body []byte) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(http.MethodPost, url, reader)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	// Bounded: this is a client talking to a box it does not control, and an
	// error body is a sentence.
	read, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return nil, response.StatusCode, err
	}
	return read, response.StatusCode, nil
}

// failureCode pulls the machine-readable half of the relay's error envelope.
func failureCode(body []byte) string {
	var value struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &value); err != nil {
		return ""
	}
	return value.Error
}

// explain renders whatever came back when it was not one of the shapes above —
// a proxy's HTML error page as often as the relay's own JSON, so it is truncated
// rather than printed whole.
func explain(body []byte) string {
	var value struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &value); err == nil && value.Message != "" {
		return value.Message
	}
	text := strings.Join(strings.Fields(string(body)), " ")
	if len(text) > 200 {
		text = text[:200] + "…"
	}
	if text == "" {
		return "(no body)"
	}
	return text
}

// describeGrantedTerms renders what came back from the exchange. It reads the
// JSON the relay sent rather than re-deriving from the local credential file,
// because the point of running this is to see what the RELAY thinks this code
// grants — which is the answer that differs when the file was edited and never
// reloaded.
func describeGrantedTerms(terms map[string]any) string {
	if len(terms) == 0 {
		return "none returned"
	}
	keys := []string{"tier", "notAfter", "queueSlots", "retentionWindowSec",
		"attachmentBytes", "concurrentTransfers", "transitBytesPerDay", "maxPerPair"}
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := terms[key]; ok {
			parts = append(parts, fmt.Sprintf("%s %v", key, value))
		}
	}
	if len(parts) == 0 {
		return "none returned"
	}
	return strings.Join(parts, " · ")
}
