# Contributors' Guide

## Introduction

Welcome to keripy's contribution guide! This project aims to develop a reference implementation of the KERI standards and protocols developed in WebOfTrust on github. We deeply appreciate the time and effort of contributors like you!

## Legal & Licensing
This project has a split license whose details are contained [here](https://github.com/WebOfTrust/ietf-keri/blob/main/LICENSE.md)

## Prerequisites
Before you start, make sure you have:

- Read the [README.md](./README.md) (best quickstart guide for using the project) and can build, install, and run the tests yourself from those instructions (from both the main and development branch).  This is the assumed baseline for any issues, proposed features, or pull requests that you wish you contribute.
- Are somewhat familiar with the [KERI, ACDC, CESR standards and the KERI whitepapers](https://github.com/WebOfTrust/keri).  Jargon isn't always the best, but it does speed communication with maintainers whose time is often in short supply and appreciate clarity in all things.  A very helpful website [kerisse.org](https://kerisse.org) has been set up to ease this process if you don't necessarily have the time to read all of those things. However, an in depth knowledge will surely help if you are looking to make a lot of contributions. 

## How to Start Contributing
The KERI community welcomes [all kinds of contributions](https://opensource.guide/how-to-contribute/).

For simple contributions like fixing typos sometimes you can just submit a naked PR with a title like "I'm fixing a spelling issue in x,y,z".  If these PRs are small often times they'll just get merged without further review.  Typos or fixing names that were mistakenly applied are human nature.

A really simple way to contribute is just to spread the word.  Let people know about KERI, create a welcoming community to newcomers by actively participating and helping with what you know, and making cools things and talking about them is helpful to grow.

Issues and discussions are meant to be discussed, commented upon.  Even a +1 to an issue that you're also experiencing can help the core maintainers decide where to focus their energies.  Discussions can help provide clarity if things aren't exactly clear.  Feel free to contribute (but also note the homework in [PREREQUISITES](#prerequisites), its frustrating for people to explain things that are already explained elsewhere).

However, this particular file is more about contributing code.  The general principal in this (and all open source really) is if you can think of a way that things might be better, instead of just suggesting it or discussing it, often times its a good idea to do some work to show what/how/when an idea might look like or contributing code/scripts/tests/issues.  Code >> discussion 9 times out of ten.  Balanced of course with the caveat not to go off into the ivory tower for months and do lots of work before presenting your work and finding out that the community doesn't like it.  Small prototypes/examples are often best.  The rest of the details of contributing code are below.

## Contribution Guidelines

### Code Style/Conventions
[PythonStyleGuide](./ref/PythonStyleGuide.md)  

### Commit Message Guidelines
There are no hard and fast guidelines but it is helpful to:
- Descriptive, to the point messages are ideal
- Link to the issue you're trying to solve with a message of how the commit does or doesn't solve that issue.
- Be sure to note important issues for checkpoint commits like "does not build"
- Most importantly, the commit message should explain the WHY of all the code changes.  When reviewing, reviewers will be confused if code changes for things you didn't list in the commit aren't there.

### Branching Strategy
Branch from development, name your feature branches something like `feature-name-of-my-feature` and bugs something like `bug-bug-name` and link the github issue that you (or someone else) should have created for most non-trivial bugs/features.  When you have fully implemented or fixed, submit a PR to WebOfTrust/keripy.  If you need feedback it can also be appropriate to submit a **draft** PR to this repository and ask for comments.

### Testing
See [README.md](README.md).  Always add tests if you fix a bug or add a feature.  This should conform to the conventions of the repository (ie if you're fixing some issue in IPEX, put your tests with the tests for IPEX).  If you're doing a greenfield implementation of something, even a few simple unit tests can provide clarity to future developers.

## Process to Submit Changes
1. Find and issue and let the developers on discord know you're working on it (and maybe comment on the issue to let people know you're picking it up).
2. Work on issue
3. Add tests
4. Submit a PR to [WebOfTrust/keripy]
5. Let maintainers know on discord in the appropriate channel
6. Come to Thursday KERI development meeting to discuss if at all possible (sometimes its easier for maintainers to provide feedback directly rather than through async text, particularly if its a large or complex change).
7. Iterate 2-6 if your change needs some fixes/updates

## Reporting Bugs or Requesting Features
- **SEARCH FOR THE BUG OR FEATURE IN THE CURRENT ISSUES IN REPO**.  If it already exists, add a comment/script/test/+1/whatever there.  Duplicates BAD.
- If the bug/feature doesn't exist create an issue wherein you describe the bug, feature, or issue with as much detail as possible (but maybe not enough that you overload the reader with details).
- Code snippets, scripts, or test cases should be added to the issue if possible.  It helps with saving maintainers time and can drastically speed the development process.
- Message in the appropriate discord channel to let people know about your bug/feature/issue, but remember that maintainers maintain at their own pace and discretion on issues of their choosing.  Its best not to ping them more than once a week.  As with all open source, if its an ultra critical bug/feature for you, cash bounties certainly incentivize people to pay attention and offer to help you directly.

## Code of Conduct and Respect
[From the discord channel](https://discord.com/channels/1148629222647148624/1148686277269532703/1148686279945498624)

We are committed to providing a friendly, safe and welcoming environment for all, regardless of level of experience, gender identity and expression, sexual orientation, disability, personal appearance, body size, race, ethnicity, age, religion, nationality, or other similar characteristic.

Please avoid using overtly sexual aliases or other nicknames that might detract from a friendly, safe and welcoming environment for all.

Please be kind and courteous. There’s no need to be mean or rude.

Respect that people have differences of opinion and that every design or implementation choice carries a trade-off and numerous costs. There is seldom a right answer.

Please keep unstructured critique to a minimum. If you have solid ideas you want to experiment with, make a fork and see how it works.

We will exclude you from interaction if you insult, demean or harass anyone. That is not welcome behavior. We interpret the term “harassment” as including the definition in the Citizen Code of Conduct; if you have any lack of clarity about what might be included in that concept, please read their definition. In particular, we don’t tolerate behavior that excludes people in socially marginalized groups.

Private harassment is also unacceptable. No matter who you are, if you feel you have been or are being harassed or made uncomfortable by a community member, please contact one of the channel admins immediately. Whether you’re a regular contributor or a newcomer, we care about making this community a safe place for you and we’ve got your back.

Likewise any spamming, trolling, flaming, baiting or other attention-stealing behavior is not welcome.
Attribution
Adapted from the Rust Code of Conduct: [https://www.rust-lang.org/policies/code-of-conduct](https://www.rust-lang.org/policies/code-of-conduct)

## Getting Help

For questions or clarifications, reach out via:
- Discord: [See KERI repo] (https://github.com/WebOfTrust/keri)
- KERI Development Meetings: [https://github.com/WebOfTrust/keri#implementors-call]
- ACDC Standards Meeting@TOIP (technically must be a member of ToIP to contribute): [https://github.com/WebOfTrust/keri#specification-call]

## Acknowledgments
Thanks to all our wonderful contributors. 

## Additional Resources

- [Project Documentation and Search Engine](https://kerisse.org)
- [Related Projects](https://github.com/WebOfTrust)
