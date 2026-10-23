# Architecture Decision Records

One file per decision, numbered sequentially: `ADR-NNNN-short-title.md`. ADRs are written by A1 after evidence has been gathered, and they are never edited after acceptance; a later ADR supersedes an earlier one.

Disagreements are resolved per CLAUDE.md section 5.7: state the competing approaches, identify assumptions and tradeoffs, determine what evidence would distinguish them, run a small experiment where practical, record the outcome here, and have A1 choose on evidence. Security and safety objections cannot be dismissed by majority agreement.

Use [ADR-0000-template.md](ADR-0000-template.md).

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [0001](ADR-0001-repository-structure-and-ownership.md) | Repository structure and module ownership | accepted |
| [0002](ADR-0002-runtime-shape.md) | Runtime shape: modular monolith with isolated collector and sensor processes | accepted |
| [0003](ADR-0003-toolchain-and-ui-stack.md) | Toolchain and UI stack | accepted |
| [0004](ADR-0004-local-persistence-and-delivery.md) | Local persistence and delivery semantics | accepted |
| [0005](ADR-0005-first-slice-scenario-and-transport.md) | First vertical slice scenario and downstream transport | accepted |
| [0006](ADR-0006-device-coverage-and-vendor-strategy.md) | Device coverage scope and vendor strategy (SEL first) | accepted |
| [0007](ADR-0007-windows-site-node.md) | Windows site node on SEL-3355-2 | proposed |
