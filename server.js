const express = require("express");
const app = express();
app.use(express.json());

app.post("/release-gate", (req, res) => {
  const violations = checkViolations(req.body);
  res.json({
    decision: violations.length === 0 ? "promote" : "block",
    violations
  });
});

function checkViolations(body) {
  const violations = [];
  const w = body.workflow;
  const image = body.image;

  // EXCESS_PERMISSION
  const expected = { contents: "read", packages: "write", "id-token": "none" };
  const perms = w.permissions || {};
  const permKeys = Object.keys(perms);
  const expKeys = Object.keys(expected);
  const permsOk =
    permKeys.length === expKeys.length &&
    expKeys.every(k => perms[k] === expected[k]);
  if (!permsOk) violations.push("EXCESS_PERMISSION");

  // UNSAFE_PR_TRIGGER
  if (body.event === "pull_request" && w.trigger === "pull_request_target") {
    violations.push("UNSAFE_PR_TRIGGER");
  }

  // TESTS_INCOMPLETE
  if (body.event === "pull_request") {
    if (!(w.testsPassed === true && w.matrixComplete === true && w.failFast === false)) {
      violations.push("TESTS_INCOMPLETE");
    }
  }

  // MUTABLE_ACTION
  const shaPattern = /^[0-9a-f]{40}$/;
  const hasMutable = (w.actions || []).some(a => {
    if (a.owner === "actions") return false;
    return !shaPattern.test(a.ref);
  });
  if (hasMutable) violations.push("MUTABLE_ACTION");

  // Image checks
  if (!image.multiStage) violations.push("SINGLE_STAGE_IMAGE");
  if (image.runsAsRoot === true) violations.push("ROOT_RUNTIME");
  if (!["none", "buildkit"].includes(image.secretMode)) violations.push("SECRET_IN_LAYER");
  if (image.criticalVulnerabilities > 0) violations.push("CRITICAL_CVE");
  if (!image.digestPinned) violations.push("UNPINNED_IMAGE");

  // Production-only checks
  if (body.target === "production") {
    if (!(body.event === "push" && body.ref === "refs/heads/main")) {
      violations.push("INVALID_PRODUCTION_REF");
    }
    if (w.environmentApproval !== true) {
      violations.push("APPROVAL_REQUIRED");
    }
  }

  return violations;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on ${PORT}`));

module.exports = app;
