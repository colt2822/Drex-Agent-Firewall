name: Bug Report
description: File a bug report or unexpected firewall behavior
title: "[BUG]: "
labels: ["bug"]
body:
  - type: markdown
    attributes:
      value: Thanks for reporting an issue! Please do not report security vulnerabilities here (see SECURITY.md).
  - type: input
    id: version
    attributes:
      label: Drex Agent Firewall Version
      placeholder: "e.g. 0.1.0"
    validations:
      required: true
  - type: textarea
    id: reproduction
    attributes:
      label: Reproduction Steps
      description: Steps or code snippet showing the issue
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected vs Actual Behavior
    validations:
      required: true
