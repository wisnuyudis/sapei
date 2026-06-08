# SAPEI

SAPEI (Secure AI Privacy Extension & Interceptor) is a local privacy interceptor for AI chat pages. It runs a local FastAPI masking service with the `openai/privacy-filter` model, then a Chrome/Edge extension intercepts prompts before they are sent to ChatGPT or similar LLM websites.

The intended default setup is local-first: each user runs the model server on their own machine and points the extension to that local API.

## What SAPEI Does

- Intercepts prompts from supported AI chat pages before sending.
- Sends the prompt to a local API endpoint.
- Masks detected private data.
- Replaces the prompt with the masked version.
- Sends the sanitized prompt to the AI chat page.

Built-in model protection works out of the box. Custom rules are optional and only needed for local/company-specific identifiers such as KTP/NIK, NPWP, account numbers, customer IDs, or internal IDs.

## Project Structure

```text
.
├── app.py                 # FastAPI local masking server
├── requirements.txt       # Python dependencies
├── extension/             # Chrome/Edge Manifest V3 extension
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html
│   ├── options.html
│   └── logo.png
└── data/policies/         # Local custom policy storage, created at runtime
```

## Requirements

- Python 3.12+ recommended
- Google Chrome or Microsoft Edge
- Enough disk space for the model cache. The first run downloads the `openai/privacy-filter` model.
- Internet connection for the first model download

## 1. Install the Local API Server

From the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2. Run the Local API Server

```bash
uvicorn app:app --host 127.0.0.1 --port 8000
```

The first startup can take several minutes because the model is downloaded and cached locally.

When the server is ready, open:

```text
http://127.0.0.1:8000/health
```

You should see a JSON response with the model and service status.

## 3. Test the API Manually

```bash
curl -X POST http://127.0.0.1:8000/mask-pii \
  -H "Content-Type: application/json" \
  -d '{"text":"Nama saya Budi, email saya budi@example.com, KTP saya 321307230900005"}'
```

Example response:

```json
{
  "masked_text": "Nama saya [PRIVATE_PERSON], email saya [PRIVATE_EMAIL], KTP saya [PRIVATE_NIK]"
}
```

## 4. Install the Browser Extension

### Chrome

1. Open `chrome://extensions`.
2. Enable `Developer mode`.
3. Click `Load unpacked`.
4. Select the `extension` folder from this project:

   ```text
   /path/to/sapei/extension
   ```

### Microsoft Edge

1. Open `edge://extensions`.
2. Enable `Developer mode`.
3. Click `Load unpacked`.
4. Select the `extension` folder.

## 5. Configure the Extension Endpoint

1. Click the SAPEI extension icon.
2. Click `Settings`.
3. In `API Connection`, set:

   ```text
   http://127.0.0.1:8000
   ```

4. Click `Save Endpoint`.

For normal local usage, this is the recommended endpoint.

## 6. Use SAPEI on ChatGPT

1. Make sure the local API server is running.
2. Open `https://chatgpt.com`.
3. Refresh the page after installing or reloading the extension.
4. Type a prompt containing private data.
5. Press Enter or click Send.

SAPEI will intercept the prompt, mask PII through the local API, replace the prompt with the sanitized text, then send it.

## Extension Popup

The popup is a status panel. It shows:

- Local API status
- Built-in protection status
- Redaction label count
- Custom rule count
- Active API endpoint
- A `Settings` button

The popup is not the main rule editor.

## Extension Settings

Open SAPEI Settings from the popup.

### Built-in Model Protection

This is enabled by default and uses:

```text
openai/privacy-filter
```

Users do not need to define rules before SAPEI works. The model detects common private data automatically.

### Redaction Labels

Redaction labels control how labels emitted by the model are rewritten.

Example:

```text
PERSON, NAME, PER -> [PRIVATE_PERSON]
EMAIL             -> [PRIVATE_EMAIL]
PHONE             -> [PRIVATE_PHONE]
SECRET            -> [SECRET]
```

These mappings do not change what the model detects. They only change the replacement text.

### Custom Rules

Custom rules are optional regex-based rules for identifiers that the model may not know.

Example NPWP rule:

```text
Name: NPWP
Regex pattern: \b\d{2}\.\d{3}\.\d{3}\.\d-\d{3}\.\d{3}\b
Replacement: [PRIVATE_NPWP]
```

Custom rules are useful for:

- KTP/NIK
- NPWP
- account numbers
- customer IDs
- employee IDs
- internal project or ticket IDs

## Local Rule Storage

By default, SAPEI stores custom policies locally under:

```text
data/policies/
```

Each browser extension installation generates an anonymous client ID. The backend uses that ID to keep custom rules separate.

This is not a user account system. It is only a local namespace for rule configuration.

## Environment Variables

Useful local variables:

```env
MODEL_NAME=openai/privacy-filter
TRANSFORMERS_LOCAL_FILES_ONLY=false
POLICY_STORAGE=local
POLICY_LOCAL_DIR=data/policies
POLICY_CACHE_TTL_SECONDS=300
```

For local-first usage, keep:

```env
POLICY_STORAGE=local
```

## Supported Sites

The extension currently injects into:

- `https://chatgpt.com/*`
- `https://chat.openai.com/*`
- `https://claude.ai/*`
- `https://gemini.google.com/*`

DOM selectors may need updates if those websites change their chat input or send button markup. The relevant selectors are in:

```text
extension/content.js
```

Look for:

```js
inputSelectors
sendButtonSelectors
```

## Troubleshooting

### The model does not load

Make sure dependencies are updated:

```bash
source .venv/bin/activate
pip install --upgrade -r requirements.txt
```

The `openai/privacy-filter` model requires a recent `transformers` version.

### The extension says the API is offline

Check that the API is running:

```bash
curl http://127.0.0.1:8000/health
```

Then verify the SAPEI Settings endpoint is:

```text
http://127.0.0.1:8000
```

### The extension does not intercept prompts

1. Reload the extension in `chrome://extensions`.
2. Refresh the ChatGPT page.
3. Open the browser console and look for:

   ```text
   [SAPEI] SAPEI is Active
   ```

If the website changed its DOM, update selectors in `extension/content.js`.

### Prompt is sent but not masked

The built-in model may not detect every local identifier. Add a Custom Rule in SAPEI Settings for that pattern.

### CORS or fetch errors

The extension sends requests through its background service worker. Make sure:

- The API endpoint is correct.
- The API server is running.
- The endpoint includes the protocol, for example `http://127.0.0.1:8000`.

## Privacy Notes

- Prompt text is sent to your configured SAPEI API endpoint.
- In the default setup, that endpoint runs locally on your own machine.
- The extension does not log raw prompt text.
- The backend should not be exposed publicly unless you understand the privacy and security implications.

## Development Commands

Check Python syntax:

```bash
python3 -m py_compile app.py
```

Check extension JavaScript:

```bash
node --check extension/background.js
node --check extension/content.js
node --check extension/popup.js
node --check extension/options.js
```

Validate the extension manifest:

```bash
python3 -m json.tool extension/manifest.json
```
