# Contributors' Guide

## Introduction

Welcome to keripy's contribution guide! This project aims to develop a reference implementation of the keri standards and protocols developed in WebOfTrust on github. We deeply appreciate the time and effort of contributors like you!

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
There are no hard and fast guidelines (TODO: is this true?) but it is helpful to:
- Link to the issue you're trying to solve with a message of how the commit does or doesn't solve that issue.
- Be sure to note important issues for checkpoint commits like "does not build"
- Most importantly, the commit message should explain the WHY of all the code changes.  When reviewing, reviewers will be confused if code changes for things you didn't list in the commit aren't there.

### Branching Strategy
Git flow.  Branch from development, name your feature branches something like `feature-name-of-my-feature` and bugs something like `bug-bug-name` and link the github issue that you (or someone else) def should have created for most non-trivial bugs.  When you have fully implemented or fixed, submit a PR to WebOfTrust/keripy.  If you need feedback it can also be appropriate to submit a **draft** PR to this repository.

### Testing
See [README.md](README.md).  Always add tests if you fix a bug or add a feature.  This should conform to the conventions of the repository (ie if you're fixing some issue in IPEX, put your tests with the tests for IPEX).  If you're doing a greenfield implementation of something, even a few simple unit tests can provide clarity to future developers.

## Process to Submit Changes
1. Find and issue and let the developers on discord know you're working on it (and maybe comment on the issue to let people know you're picking it up).
2. Work on issue
3. Add tests
4. Submit a PR to [WebOfTrust/keripy]
5. Let maintainers know on discord in the appropriate channel
6. Come to Thursday Keri development meeting to discuss if at all possible (sometimes its easier for maintainers to provide feedback directly rather than through async text, particularly if its a large or complex change).
7. Iterate 2-6 if your change needs some fixes/updates

## Reporting Bugs or Requesting Features
- **SEARCH FOR THE BUG OR FEATURE IN THE CURRENT ISSUES IN REPO**.  If it already exists, add a comment/script/test/+1/whatever there.  Duplicates BAD.
- If the bug/feature doesn't exist create an issue wherein you describe the bug, feature, or issue with as much detail as possible (but maybe not enough that you overload the reader with details).
- Code snippets, scripts, or test cases should be added to the issue if possible.  It helps with saving maintainers time and can drastically speed the development process.
- Message in the appropriate discord channel to let people know about your bug/feature/issue, but remember that maintainers maintain at their own pace and discretion on issues of their choosing.  Its best not to ping them more than once a week.  As with all open source, if its an ultra critical bug/feature for you, cash bounties certainly incentivize people to pay attention and offer to help you directly.

## Code of Conduct and Respect
Treat people with respect.  (TODO: Should we add a more complex code of conduct?)

## Getting Help

For questions or clarifications, reach out via:
- Discord: [https://discord.gg/SNBnzwac]
- KERI Development Meetings: [https://github.com/WebOfTrust/keri#implementors-call]
- ACDC Standards Meeting@TOIP (technically must be a member of ToIP to contribute): [https://github.com/WebOfTrust/keri#specification-call]

## Acknowledgments
Thanks to all our wonderful contributors. 

## Additional Resources

- [Project Documentation](kerisse.org)
- [Related Projects](https://github.com/WebOfTrust)

## Legal & Licensing
This project is licensed under the [Apache License 2.0](LICENSE)  See LICENSE file in this repo for details.
