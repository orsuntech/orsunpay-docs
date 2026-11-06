# OrsunPay documentation

This is the source for [docs.orsunpay.com](https://docs.orsunpay.com), published by OrsunTech. It covers the OrsunPay merchant API, payment methods, hosted checkout, merchant cabinet and operator backoffice.

Edit the MDX page and add its path to `docs.json` when introducing a new guide. API schemas come from the OrsunPay gateway's OpenAPI exporter. The videos are recordings of OrsunPay using synthetic data.

From the repository root, run `npx mint@4.2.1206 dev` to preview your changes. Run `npx mint@4.2.1206 validate` and `npx mint@4.2.1206 broken-links` before merging. Mintlify publishes the root of `main` to the custom domain.
