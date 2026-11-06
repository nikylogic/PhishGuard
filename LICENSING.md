# Licensing

PhishGuard is **free for people** and **paid for businesses**. The code is public so anyone can read it, check it and help improve it.

It is released under the [PolyForm Noncommercial License 1.0.0](LICENSE). That makes it *source-available*, not "open source" in the OSI sense, because businesses need a paid license.

## Free: no license needed

| Who | Free? |
|---|---|
| You, protecting your own PC and your family's | ✅ |
| Students, hobbyists, researchers, security learners | ✅ |
| Schools, colleges and universities | ✅ |
| Charities and non-profits | ✅ |
| Government bodies, police, CERTs, public health and safety organisations | ✅ |
| Journalists and researchers publishing for the public good | ✅ |

You may also change the code and share your changes, for these same purposes. Keep the [LICENSE](LICENSE) file and its `Required Notice:` lines.

## Paid: commercial license needed

| Who | Example |
|---|---|
| A company using PhishGuard on its staff's computers | An IT team installing it on office PCs |
| A business offering PhishGuard to its customers | A bank, MSP or security vendor bundling it or running it as a service |
| A freelancer or consultant using it in paid client work | Checking links as part of a paid audit |
| Building a commercial product on PhishGuard's code or its AI Guard model | |

A commercial license covers the PhishGuard code and the AI Guard model. To ask for one, open a [commercial license request](https://github.com/nikylogic/PhishGuard/issues/new?template=commercial-license.yml); it only asks for your organisation's name and size, and the details are then taken private.

## Third-party data in business copies

PhishGuard downloads public phishing lists. Their owners set their own terms:

| List | Terms | In a business copy |
|---|---|---|
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) | MIT | Used |
| [phishunt.io](https://phishunt.io) | CC0 | Used |
| [OpenPhish](https://openphish.com) community feed | Non-commercial use only | **Left out**, unless the business has its own OpenPhish license |

A business copy runs with `PHISHGUARD_BUSINESS=1`, which leaves out the non-commercial lists. Everything else works the same.

## Contributions

Contributors sign a short [Contributor License Agreement](CLA.md) once, on their first pull request. It lets PhishGuard stay free for people while being licensed to businesses; you keep the copyright in your work. See [CONTRIBUTING.md](CONTRIBUTING.md).

*This page is a plain-language summary. If it and the [LICENSE](LICENSE) ever disagree, the LICENSE wins.*
