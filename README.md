# daggerverse Cosign Module

[Dagger](https://dagger.io/) module for [daggerverse](https://daggerverse.dev/) providing [Cosign](https://github.com/sigstore/cosign) functionality.

The Dagger module is located in the [cosign](./cosign/) directory.

## usage

Basic usage guide.

The [cosign](./cosign/) directory contains a [daggerverse](https://daggerverse.dev/) [Dagger](https://dagger.io/) module.

Check the official Dagger Module documentation: https://docs.dagger.io/

The [Dagger CLI](https://docs.dagger.io/cli) is needed.

### functions

List all functions of the module. This command is provided by the [Dagger CLI](https://docs.dagger.io/cli). 

```bash
dagger functions -m ./cosign/
```

The helm module is referenced locally.

See the module [readme](./helm/README.md) or the method comments for more details.

## development

Basic development guide.

### setup Dagger module

Setup the Dagger module.

Create the directory for the module and initialize it.

```bash
mkdir cosign/
cd cosign/

# initialize Dagger module
dagger init
dagger develop --sdk go --source cosign
```

## To Do

- [ ] Add more tools
- [ ] Add cache mounts
- [ ] Add environment variables
- [ ] Add more examples
- [ ] Add tests
