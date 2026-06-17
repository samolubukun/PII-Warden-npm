import PIIWarden from './index.js';

async function runTest() {
  console.log("Initializing PII Warden...");
  const warden = new PIIWarden();

  console.log("\n--- Running Tier 1 (Local Rules Only) ---");
  const test1 = await warden.analyze("My credit card is 4111-1111-1111-1111 and email is sam@example.com");
  console.log("Original: ", test1.originalText);
  console.log("Redacted: ", test1.redactedText);
  console.log("Entities: ", JSON.stringify(test1.entities, null, 2));

  console.log("\n--- Loading Tier 2 ONNX ML Model ---");
  await warden.loadModel();
  console.log("Model loaded successfully!");

  console.log("\n--- Running Tier 2 (Hybrid Regex + ML) ---");
  const test2 = await warden.analyze("My name is Samuel Olubukun and my phone number is +1-555-0199");
  console.log("Original: ", test2.originalText);
  console.log("Redacted: ", test2.redactedText);
  console.log("Entities: ", JSON.stringify(test2.entities, null, 2));
}

runTest().catch(console.error);
