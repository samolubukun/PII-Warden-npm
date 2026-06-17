# 🛡️ PII Warden

[![npm version](https://img.shields.io/npm/v/pii-warden.svg)](https://www.npmjs.com/package/pii-warden)
[![npm downloads](https://img.shields.io/npm/dm/pii-warden.svg)](https://www.npmjs.com/package/pii-warden)
[![license](https://img.shields.io/npm/l/pii-warden.svg)](https://github.com/samolubukun/PII-Warden-npm/blob/main/LICENSE)

Privacy-first, client-side PII (Personally Identifiable Information) detection and redaction engine for web browsers and Node.js. 

It combines **160+ local regex/checksum patterns** with **client-side ONNX machine learning models** using Hugging Face's Transformers.js.

---

## Features

- **Hybrid Two-Tier Engine**: 
  - **Tier 1 (Instant & Offline)**: Identifies structured data (Credit Cards, Emails, Phone Numbers, Social Security Numbers, Passport IDs) using fast regexes and mathematical checksum validation (Luhn, Modulo 97, etc.).
  - **Tier 2 (Context-Aware ML)**: Uses a fine-tuned token classification model (DistilBERT) executing client-side via ONNX Runtime Web to detect names, organizations, and addresses.
- **Deduplication & Collision Resolution**: Auto-merges overlapping matches and resolves boundary clashes between local rules and machine learning predictions.
- **Privacy First**: Zero API servers or network hops required for inference. The machine learning model is downloaded directly to the browser cache and executes locally.

---

## Installation

```bash
npm install pii-warden
```

---

## Usage

### 1. Basic (Offline / Rules Only)
For fast, offline-capable verification of credit cards, emails, phone numbers, and country-specific IDs.

```javascript
import PIIWarden from 'pii-warden';

const warden = new PIIWarden();

const result = await warden.analyze("Please contact support at sam@example.com.");
console.log(result.redactedText);
// -> "Please contact support at [EMAIL_1]."
```

### 2. Hybrid (With Client-Side ML NER)
To enable name, location, and organization detection, load the ONNX machine learning model. The model files will be downloaded once to the browser cache and execute fully inside the user's browser tab.

```javascript
import PIIWarden from 'pii-warden';

const warden = new PIIWarden();

// Warm up and load the ML model locally
await warden.loadModel();

const result = await warden.analyze(
  "My name is Samuel Olubukun and my email is sam@example.com."
);

console.log(result.redactedText);
// -> "My name is [ID_1] [ID_2] and my email is [EMAIL_1]."

console.log(result.entities);
/*
[
  { entity_type: 'FIRSTNAME', text: 'Samuel', start: 11, end: 17, score: 0.94 },
  { entity_type: 'LASTNAME', text: 'Olubukun', start: 18, end: 26, score: 0.92 },
  { entity_type: 'EMAIL', text: 'sam@example.com', start: 44, end: 59, score: 1.0 }
]
*/
```

---

## Configuration

You can customize minimum thresholds and patterns during instantiation:

```javascript
const warden = new PIIWarden({
  minScores: {
    EMAIL: 0.9,
    PHONE: 0.85
  },
  modelName: 'samuelolubukun/pii-ner-edge-optimized' // Path to your custom ONNX NER model
});
```

---

## Real-Time Form/Input Integration Example

You can easily bind the detector to textareas, inputs, or contenteditable divs to alert users or sanitize inputs on the fly:

```html
<textarea id="chat-input" placeholder="Type message..."></textarea>
<div id="warning-msg" style="color: #ff3333; display: none; margin-top: 5px;">
  ⚠️ Warning: Sensitive PII detected!
</div>

<script type="module">
  import PIIWarden from 'pii-warden';

  const warden = new PIIWarden();
  
  // Warm up and load the ML model locally
  await warden.loadModel(); 

  const inputEl = document.getElementById('chat-input');
  const warningEl = document.getElementById('warning-msg');

  inputEl.addEventListener('input', async () => {
    const result = await warden.analyze(inputEl.value);
    
    if (result.entities.length > 0) {
      // Alert user
      warningEl.style.display = 'block';
      
      // Optional: Auto-redact in place
      // inputEl.value = result.redactedText;
    } else {
      warningEl.style.display = 'none';
    }
  });
</script>
```

---

## Model Details & Provenance

The ML component of the hybrid engine uses a dual-stage architecture optimization:

* **Base Model:** The core classification is powered by [`samuelolubukun/pii-ner-finetuned-distilbert`](https://huggingface.co/samuelolubukun/pii-ner-finetuned-distilbert). This model is a fine-tune of **DistilBERT** trained on top of **AI4Privacy's** high-quality multilingual PII dataset, optimized for Token Classification (NER).
* **Edge ONNX Model:** To support fast, zero-latency, in-browser execution, the base model is quantized and compiled using Hugging Face's **Optimum** toolchain to create [`samuelolubukun/pii-ner-edge-optimized`](https://huggingface.co/samuelolubukun/pii-ner-edge-optimized).
  * **Quantization:** INT8 quantization is applied to reduce the model size from **~260MB** down to **~67MB**.
  * **Performance:** This allows the model to download quickly, run on standard user devices using WebAssembly ONNX Runtime Web, and complete inferences client-side with negligible accuracy loss.

---

## License

MIT
