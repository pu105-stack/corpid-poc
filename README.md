# CorpID Sandbox – Proof of Concept

A demo application for the Hong Kong Government's **CorpID Sandbox Programme**,
built to test Corporate Identity Verification.

---

## What is this?

In Hong Kong, when a company wants to use an online government service, someone
needs to prove two things:

1. **Who they are** — their personal identity (handled by **iAM Smart**)
2. **Which company they represent** — their corporate identity (handled by **CorpID**)

This demo shows how both happen in a single login flow, using your phone.

---

## What is iAM Smart?

**iAM Smart** is Hong Kong's personal digital identity platform — think of it as
a digital version of your HKID card on your phone. It lets you prove who you are
to online services without typing in passwords.

---

## What is CorpID?

**CorpID** is the corporate version of iAM Smart. It is being developed by the
Digital Policy Office (DPO) and links a person to the company they are authorised
to represent. Instead of filling in your company's Business Registration Number
and details every time, CorpID can verify and share that information automatically.

---

## How does the login work?

Think of it like showing two cards at a reception desk:

```
Step 1 — Show your personal ID card
         The system displays a QR code on screen.
         You scan it with the iAM Smart app on your phone and tap Approve.
         → The system now knows WHO you are.

Step 2 — Show your company authorisation card
         The iAM Smart app automatically opens the CorpID mini-program.
         CorpID checks that you are an authorised representative of your company.
         → The system now knows WHICH COMPANY you represent.

Step 3 — You are logged in
         The website confirms your identity and your company's identity.
         You receive a unique ID token that represents you + your company
         on this service.
```

---

## Why are two systems involved?

CorpID does not have its own login screen — it is deliberately built on top of
iAM Smart. The reasoning is:

- iAM Smart already handles secure personal identity for millions of Hong Kong residents
- CorpID adds the corporate layer on top, rather than duplicating the personal ID infrastructure
- One phone app (iAM Smart) handles both personal and corporate verification

---

## What does this demo show?

| Feature | Status |
|---|---|
| Corporate Identity Verification (login) | ✅ Implemented |
| Form Pre-filling (auto-fill company details) | 🔜 Coming next |
| Digital Signing | 🔜 Future |

After a successful login, the demo displays:

- **openID** — a unique token representing this user on your service (used like a user ID in your database)
- **User Type** — whether the user has standard or signing capability
- **Scope** — what permissions were granted

---

## What do you need to run it?

| Requirement | Where to get it |
|---|---|
| CorpID Sandbox account | CorpID Sandbox Developer Portal |
| CorpID Client ID + Secret | Developer Portal → Account → User Credentials |
| iAM Smart ITE account | Automatically created when you registered for CorpID Sandbox (check your email) |
| iAM Smart Client ID + Secret | iAM Smart ITE self-service portal (link in the email) |
| iAM Smart testing app | Download APK from CorpID Sandbox Portal → Guides and Tutorials |
| Android phone | Required to run the iAM Smart testing app |

---

## Developer Setup

```bash
# 1. Install dependencies
npm install

# 2. Copy the example config and fill in your credentials
cp .env.example .env
# Edit .env — add your Client IDs and Secrets

# 3. Start the server
npm start

# 4. Open in browser
open http://localhost:3000
```

---

## Project Structure

```
corpid-poc/
├── src/
│   ├── server.js      # Web server and login routes
│   ├── corpid.js      # CorpID API integration
│   ├── iamsmart.js    # iAM Smart API integration
│   └── crypto.js      # Encryption / security layer
├── public/
│   └── index.html     # Demo web page
└── .env.example       # Configuration template
```

---

## Background

The CorpID Sandbox Programme was launched in December 2025 by the Digital Policy
Office in collaboration with Cyberport. It allows companies and developers to test
CorpID integration before the full platform launches in late 2026.

Typical use cases include:
- **Remote account opening** — verify a company's identity without paper documents
- **Online service login** — let companies log in to government portals securely
- **Form pre-filling** — automatically populate company details on application forms
- **Digital signing** — sign contracts and agreements with legal backing
