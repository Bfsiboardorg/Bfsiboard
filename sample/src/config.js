// Sample file with FAKE secrets for local testing.
// Every credential below is fabricated — do not use anywhere.

module.exports = {
  // AWS access key pattern (fake)
  awsAccessKey: "AKIAABCDEFGHIJKLMNOP",

  // AWS secret access key (fake, 40-char value)
  awsSecret: "aws_secret_access_key = AWSFAKESECRETKEYABCDEFGHIJKLMNOPQRSTUVWX",

  // GitHub PAT (fake)
  githubToken: "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",

  // Stripe live key (fake)
  stripe: "sk_live_ABCDEFGHIJKLMNOP",

  // Personal data (fake)
  email: "privacy.test@example.com",
  phone: "+91 9876543210",
  aadhaar: "2345 6789 0123",
  pan: "ABCDE1234F",
};
