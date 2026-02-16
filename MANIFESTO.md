**Sigilum**

Auditable Identity for AI Agents

*A manifesto for why this needs to exist*

## **How We Got Here, Fast**

Four years ago, the best AI models were predicting grammatically correct sentences. GPT-3 could write a convincing paragraph but couldn’t do anything with it. Then OpenAI introduced function calling, and models could reach into external systems, query databases, pull records. Then came reasoning architectures, models like Claude and GPT-4 chaining observations and actions in loops, working through multi-step problems autonomously. Then Codex, Claude Code, and similar coding engines gave models the ability to write and execute production-grade software. Now, with OpenClaw, personal AI agents run locally on your operating system with full access to your files, email, browser, and code execution. And on Moltbook, those agents interact with each other autonomously in a public forum, posting, commenting, and forming communities with no humans in the loop. Agents with real system access, talking to other agents, unsupervised.

The capability curve outran the trust infrastructure. We went from language models to autonomous personal agents in roughly four years, and the identity and accountability layer that should have been built alongside that progression simply wasn’t. We’re now deploying agents into regulated, high-stakes environments using trust primitives, shared API keys, service accounts, platform-level credentials, that were designed for a world where software didn’t make its own decisions.

That gap is what Sigilum exists to close.

## **The Situation We’re In**

Most of what AI agents do today is automation in controlled environments. They look up customer data, process routine requests, execute predefined workflows. They act as sophisticated API callers inside a company’s own stack. The scenario of fully autonomous agents roaming free across mission-critical systems has not yet arrived.

But even in these controlled environments, something fundamental is missing. When an AI agent makes a call to a core system, whether that’s a banking platform, a hospital’s electronic health records, an insurance claims processor, or an enterprise resource planning system, the receiving system has no reliable way to answer three basic questions: Which agent is this? Who authorized it to act? And what chain of delegation does it represent?

Today, the answer to all three is usually a shared API key or a service account. That identifies the platform, not the agent. Every agent running through a given integration looks identical to the downstream system. A customer service agent and a fraud detection agent and a compliance monitoring agent all present the same credential. The system they’re calling has no way to distinguish between them, scope them differently, or trace an action back to a specific agent acting under a specific authorization.

This works until it doesn’t. And in regulated industries, from financial services to healthcare to critical infrastructure, the moment it stops working tends to be expensive.

## **The Accountability Problem**

We published a piece at Payman called “Accountability Decay at Machine Speed.” The core argument is that in multi-agent architectures, accountability dissolves through delegation. Agent A calls Agent B, which triggers Agent C, which writes and deploys code or executes a transaction. By the time something breaks, the originating authorization has passed through enough layers that no one can say with confidence who is responsible.

This is a familiar failure pattern. Financial derivatives laundered risk through layers of abstraction until it became orphaned. Social media virality diffused responsibility for harmful content across algorithms, platforms, and users until it belonged to no one. Agent chains do the same thing, except they do it in seconds.

The standard response to this is “build better guardrails.” Train the models more carefully. Add safety layers. Filter the outputs. That work matters, but it addresses agent behavior in isolation. It does nothing about the structural problem, which is that a chain of agents executing in sequence has no inherent mechanism for tracing authority back to its source.

An agent can behave perfectly within its own scope and still contribute to a catastrophic outcome because the chain it’s part of was never designed to be auditable. Like that popular Marvel character with the perfectly logical plan to save the universe by destroying half of it: coherent reasoning at every step, devastating outcome at the end. Each agent in the sequence is doing exactly what it was told to do. The problem is that no one can reconstruct who told whom, or where human authorization ended and autonomous execution began.

## **Alignment Is Necessary but Not Sufficient**

Frontier model companies, Anthropic, OpenAI, Google DeepMind, are investing heavily in alignment research. They are doing genuinely important work to ensure that models behave safely, follow instructions faithfully, and refuse harmful requests. This work matters and should continue.

But alignment alone does not solve the accountability problem. A well-aligned agent that follows its instructions perfectly can still participate in a delegation chain that produces a catastrophic outcome, because the chain itself was never designed to be auditable or interruptible. Alignment governs how an individual agent behaves. It says nothing about how a system of agents should be governed.

Consider the analogy to automobiles. Car manufacturers invest billions in safety engineering: airbags, crumple zones, collision avoidance, lane departure warnings. These features save lives. But no society has ever said “the cars are safe enough, so we don’t need traffic laws, speed limits, driver’s licenses, or traffic cameras.” We trust the engineering, and we verify through infrastructure. The safety features in the vehicle and the rules of the road are complementary systems. One does not replace the other.

AI agents are in a similar position. Alignment is the safety engineering inside the vehicle. Sigilum is the infrastructure on the road: the license that identifies who is driving, the registration that traces the vehicle to its owner, and the cameras that record what happens when something goes wrong. Trust but verify requires mechanisms to verify. Right now, those mechanisms do not exist for AI agents.

## **Why This Is an Identity Problem**

Accountability requires identity. You cannot hold a system accountable if you cannot identify the actors within it. And right now, AI agents are essentially anonymous. They inherit the identity of the platform that deploys them, which is like identifying every employee at a company by the company’s name rather than their own.

This matters across every regulated industry. Bank examiners will ask how an institution can prove that an AI agent acting on a customer’s account was specifically authorized to perform that specific action. Healthcare auditors will ask how a hospital can demonstrate that an agent accessing patient records had proper authorization under HIPAA. Insurance regulators will want to know which agent processed a claim and under whose authority. In every case, “we gave the platform an API key” is not a sufficient answer. These industries need per-agent, per-action traceability. They need to know which agent did what, under whose authority, and be able to prove it after the fact.

This is what Sigilum is for. Every AI agent gets an auditable identity. Every action that agent takes can be verified against that identity. Every delegation from a human or another agent is signed, creating a chain of custody that can be reconstructed at any point. When a regulator or an auditor asks “who authorized this,” the answer is traceable all the way back to a human decision.

## **What Sigilum Does and Does Not Do**

Sigilum is an identity and delegation layer. It answers the question “who is this agent and who authorized it to act?” It does not manage what the agent is allowed to do. That stays with the service provider, where it belongs.

The analogy is OAuth. OAuth doesn’t know what “read:email” means. Gmail defines that scope. OAuth provides the framework for requesting, granting, and verifying that a scope was authorized. Similarly, Sigilum doesn’t know what “read account balance” means inside a core banking system, or what “access patient record” means inside an EHR platform, or what “process claim” means inside an insurance system. Those systems define their own permissions. Sigilum gives them a verified, cryptographic input they can use to make their own authorization decisions: this is Agent X, delegated by Human Y, through Platform Z, and here is the signed chain to prove it.

This makes adoption realistic. Service providers do not need to migrate their authorization logic into a new system. They gain a missing input, verified agent identity with a delegation chain, that plugs into whatever authorization system they already run.

## **The Hard Problems Underneath the Simple Idea**

Auditable identity for AI agents sounds straightforward. So did SSL for websites, and the ecosystem that grew around that, including certificate authorities, chains of trust, revocation infrastructure, browser trust stores, and Let’s Encrypt, became foundational internet infrastructure. The primitive was simple. Implementing it in practice surfaced genuinely hard problems. Agent identity has its own set of hard problems, and they’re specific to agents in ways that make this different from replicating PKI for bots.

**Ephemeral identity.** A website has a stable domain name. An AI agent is ephemeral. It can be spun up and destroyed in milliseconds, cloned across infrastructure, and run as one of ten thousand concurrent instances. What is the stable identifier for something that may not exist five seconds from now? This is a genuinely unsolved problem and one that Sigilum needs to address at the protocol level.

**The meaning of human approval.** “I approve this agent” can mean many different things. A bank administrator approving an agent class for deployment is fundamentally different from a patient consenting to an agent accessing their health records, which is different again from a claims adjuster authorizing an agent to process a specific case. Each of these has different UX implications, different security requirements, and different infrastructure needs. Sigilum needs to support all of them coherently.

**Revocation at machine speed.** If an agent is compromised or behaving badly, how fast can you kill its identity? In traditional PKI, revocation is notoriously slow. Certificate revocation lists and OCSP have well-documented latency and reliability problems. For agents operating at machine speed, you need revocation that works at machine speed. A compromised agent that retains a valid identity for even a few minutes can do enormous damage in a regulated environment.

**Trust registries.** How does a receiving system know which Sigilum identities to accept? Who decides which platforms are trusted issuers? This is a governance problem as much as a technical one. In banking, industry bodies like the ICBA could establish shared trust frameworks for their member institutions. In healthcare, similar consortia could define which agent platforms are authorized to interact with clinical systems. The governance layer is what makes the cryptographic layer useful, and it will look different in every industry.

## **The Sequence**

Sigilum’s ambition is to become foundational infrastructure for agent identity, the way SSL became foundational infrastructure for web trust. But infrastructure like that gets built in stages, and the first stage has to solve a problem people already have.

Today, the problem is that regulated institutions deploying AI agents cannot prove to examiners, auditors, or their own compliance teams which agent did what, under whose authority. The immediate version of Sigilum solves that: verifiable agent identity and delegation chains for controlled environments where agents operate within a company’s own infrastructure.

As agent architectures evolve, as delegation chains get longer, as agents begin calling agents across organizational boundaries, the identity and delegation problem gets harder and more consequential. The same protocol that today helps a bank prove to regulators that its customer service agent was properly authorized becomes, over time, the protocol that enables cross-vendor agent trust, machine-speed revocation, and auditable multi-agent chains operating at scale across industries.

Accountability decays at machine speed. Sigilum exists to make sure identity doesn’t.