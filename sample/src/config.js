// Sample file with FAKE secrets for local testing.
// Every credential below is fabricated â€” do not use anywhere.

module.exports = {
  // AWS access key pattern (fake)
  awsAccessKey: "AKIA__FAKE_AWS_KEY__",

  // AWS secret access key (AWS's documented example value)
  awsSecret: "aws_secret_access_key = __AWS_FAKE_SECRET_KEY__",

  // GitHub PAT (fake)
  githubToken: "ghp__FAKE_GITHUB_PAT__",

  // Stripe live key (fake)
  stripe: "sk_test__FAKE_STRIPE_KEY__",

  // Personal data (fake)
  email: "privacy.test@example.com",
  phone: "+91 9876543210",
  aadhaar: "2345 6789 0123",
  pan: "ABCDE1234F",
};
