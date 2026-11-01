import { type FormEvent, useRef, useState } from "react";

import { ApiError, api } from "../api/client";
import { Button, StatePanel, TextInput } from "../ds/components";
import {
  type CredentialStore,
  KeyPromptError,
  type SessionClient,
  submitPassword,
  submitTotp,
  submitWebAuthn,
  webAuthnAvailable,
} from "./session";

type Step = "password" | "code";

function messageOf(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "Sign-in failed. Check the details and try again.";
    if (error.status === 429) return "Too many attempts. Wait a moment, then try again.";
    if (error.status === 501) return "Sign-in is not available on this server yet.";
    if (error.status === 400) return error.problem.detail ?? error.problem.title;
    return "The server could not complete the sign-in. Try again.";
  }
  return "Can't reach the server. Check your connection, then try again.";
}

/**
 * The console sign-in: the break-glass account's password (AN-8), then its second factor, an authenticator code
 * or a security key (AN-10). Failures use the server's one generic answer, so the screen never says which part was wrong.
 */
export function SignInPage({
  client = api,
  onSignedIn,
  credentials,
}: {
  /** Stands in for the browser's credential store (tests). */
  readonly credentials?: CredentialStore;
  readonly client?: SessionClient;
  /** Called once a session exists. */
  readonly onSignedIn: () => void;
}) {
  const [step, setStep] = useState<Step>("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [fieldError, setFieldError] = useState<string>();
  const codeInput = useRef<HTMLInputElement>(null);

  const useKey = async () => {
    if (busy) return;
    setError(undefined);
    setFieldError(undefined);
    setBusy(true);
    try {
      await submitWebAuthn(client, credentials);
      onSignedIn();
      return;
    } catch (err) {
      if (err instanceof KeyPromptError) {
        setError("The security key was not used. Touch your key when asked, or enter a code.");
      } else {
        setError(messageOf(err));
        // The server may have used up the pending sign-in; start over on a refusal.
        if (err instanceof ApiError && err.status === 401) {
          setStep("password");
          setCode("");
        }
      }
    }
    setBusy(false);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setError(undefined);
    setFieldError(undefined);
    if (step === "password") {
      if (username.trim() === "" || password === "") {
        setFieldError(username.trim() === "" ? "Enter your account name." : "Enter your password.");
        return;
      }
    } else if (code.trim() === "") {
      setFieldError("Enter the code from your authenticator.");
      return;
    }
    setBusy(true);
    try {
      if (step === "password") {
        await submitPassword(client, username.trim(), password);
        setPassword("");
        setStep("code");
        setTimeout(() => codeInput.current?.focus(), 0);
      } else {
        await submitTotp(client, code.trim());
        onSignedIn();
        return;
      }
    } catch (err) {
      setError(messageOf(err));
      // A failed code may have used up the pending sign-in; the safe move is to start over.
      if (step === "code" && err instanceof ApiError && err.status === 401) {
        setStep("password");
        setCode("");
      }
    }
    setBusy(false);
  };

  return (
    <main className="diq-page diq-page--narrow">
      <h1 className="diq-page__title">Sign in to activeDIQ</h1>
      <form onSubmit={submit} noValidate>
        {error !== undefined && (
          <StatePanel tone="error" title="Couldn't sign you in">
            <p>{error}</p>
          </StatePanel>
        )}
        {step === "password" ? (
          <>
            <TextInput
              label="Account name"
              autoComplete="username"
              autoFocus
              spellCheck={false}
              value={username}
              error={fieldError?.includes("account") ? fieldError : undefined}
              onChange={(e) => setUsername(e.target.value)}
            />
            <TextInput
              label="Password"
              type="password"
              autoComplete="current-password"
              value={password}
              error={fieldError?.includes("password") ? fieldError : undefined}
              onChange={(e) => setPassword(e.target.value)}
            />
          </>
        ) : (
          <TextInput
            label="Authenticator code"
            inputRef={codeInput}
            inputMode="numeric"
            autoComplete="one-time-code"
            spellCheck={false}
            value={code}
            error={fieldError}
            onChange={(e) => setCode(e.target.value)}
          />
        )}
        <p>
          <Button type="submit" variant="primary" loading={busy}>
            {step === "password" ? "Continue" : "Sign in"}
          </Button>
          {step === "code" && webAuthnAvailable(credentials) && (
            <Button type="button" onClick={() => void useKey()} disabled={busy}>
              Use a security key
            </Button>
          )}
        </p>
      </form>
    </main>
  );
}
