# nextendo-account (nx-mod testing)

nx-mod's `testing` fork of [nextendo-account](https://github.com/NextendoNetwork/nextendo-account): The Nextendo Network account server — identities, friends, presence, BCAT. Go.
Part of [nextendo-testing](https://github.com/nx-mod/nextendo-testing): the whole Nextendo Network, run on a LAN. Upstream's README is kept as [README.upstream.md](README.upstream.md).

## nx-mod changes

- **Local open mode** (`NEXTENDO_LOCAL_OPEN=1`): an unknown NSA id or PID gets an account, new accounts are e-mail verified, every account is friends with every other, and any e-mail + password signs in (the first login creates the account) — on the site and from the console's account-link page.
- **RS256 BaaS id_tokens** minted locally, so a real Switch can link without Nintendo.
- ARMS and Super Mario Maker 2 access keys and stats wiring; `s2_save` builds on 32-bit targets.

## Credits

nextendo-account is the work of the **Nextendo Network team** — https://nextendo.network. nx-mod only adds the changes above, for LAN testing. Nextendo is awesome.
