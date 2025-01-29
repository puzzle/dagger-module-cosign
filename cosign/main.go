// Cosign container image signing in a Dagger module
package main

import (
	"context"
	"dagger/cosign/internal/dagger"
	"fmt"
	"time"
)

// Cosign represents the cosign Dagger module type
type Cosign struct{}

// Sign will run cosign sign from the image, as defined by the cosignImage
// parameter, to sign the given Container image digest
//
// See https://edu.chainguard.dev/open-source/sigstore/cosign/an-introduction-to-cosign/
func (f *Cosign) Sign(
	ctx context.Context,
	// Cosign private key
	privateKey dagger.Secret,
	// Cosign password
	password dagger.Secret,
	// registry username
	//+optional
	registryUsername *string,
	// name of the image
	//+optional
	registryPassword *dagger.Secret,
	// Docker config
	//+optional
	dockerConfig *dagger.File,
	// Cosign container image
	//+optional
	//+default="chainguard/cosign:latest"
	cosignImage *string,
	// Cosign container image user
	//+optional
	//+default="nonroot"
	cosignUser *string,
	// Container image digest to sign
	digest string,
) (string, error) {
	return f.sign(ctx, privateKey, password, registryUsername, registryPassword, dockerConfig, cosignImage, cosignUser, digest)
}

// SignKeyless will run cosign sign from the image, as defined by the cosignImage
// parameter, to sign the given Container image digest
//
// See https://edu.chainguard.dev/open-source/sigstore/cosign/an-introduction-to-cosign/
func (f *Cosign) SignKeyless(
	ctx context.Context,
	// registry username
	//+optional
	registryUsername *string,
	// name of the image
	//+optional
	registryPassword *dagger.Secret,
	// Docker config
	//+optional
	dockerConfig *dagger.File,
	// Cosign container image
	//+optional
	//+default="chainguard/cosign:latest"
	cosignImage *string,
	// Cosign container image user
	//+optional
	//+default="nonroot"
	cosignUser *string,
	// Container image digest to sign
	digest string,
) (string, error) {
	return f.sign(ctx, dagger.Secret{}, dagger.Secret{}, registryUsername, registryPassword, dockerConfig, cosignImage, cosignUser, digest)
}

// Attest will run cosign attest from the image, as defined by the cosignImage
// parameter, to attest the SBOM of the given Container image digest
//
// See https://edu.chainguard.dev/open-source/sigstore/cosign/how-to-sign-an-sbom-with-cosign/
func (f *Cosign) Attest(
	ctx context.Context,
	// Cosign private key
	privateKey dagger.Secret,
	// Cosign password
	password dagger.Secret,
	// registry username
	//+optional
	registryUsername *string,
	// name of the image
	//+optional
	registryPassword *dagger.Secret,
	// Docker config
	//+optional
	dockerConfig *dagger.File,
	// Cosign container image
	//+optional
	//+default="chainguard/cosign:latest"
	cosignImage *string,
	// Cosign container image user
	//+optional
	//+default="nonroot"
	cosignUser *string,
	// Container image digest to attest
	digest string,
	// SBOM file
	predicate *dagger.File,
	// SBOM type (slsaprovenance|slsaprovenance02|slsaprovenance1|link|spdx|spdxjson|cyclonedx|vuln|openvex|custom) or an URI
	//+optional
	//+default="spdxjson"
	sbomType string,
) (string, error) {
	return f.attest(ctx, privateKey, password, registryUsername, registryPassword, dockerConfig, cosignImage, cosignUser, digest, predicate, sbomType)
}

// AttestKeyless will run cosign attest from the image, as defined by the cosignImage
// parameter, to attest the SBOM of the given Container image digest
//
// See https://edu.chainguard.dev/open-source/sigstore/cosign/how-to-sign-an-sbom-with-cosign/
func (f *Cosign) AttestKeyless(
	ctx context.Context,
	// registry username
	//+optional
	registryUsername *string,
	// name of the image
	//+optional
	registryPassword *dagger.Secret,
	// Docker config
	//+optional
	dockerConfig *dagger.File,
	// Cosign container image
	//+optional
	//+default="chainguard/cosign:latest"
	cosignImage *string,
	// Cosign container image user
	//+optional
	//+default="nonroot"
	cosignUser *string,
	// Container image digest to attest
	digest string,
	// SBOM file
	predicate *dagger.File,
	// SBOM type (slsaprovenance|slsaprovenance02|slsaprovenance1|link|spdx|spdxjson|cyclonedx|vuln|openvex|custom) or an URI
	//+optional
	//+default="spdxjson"
	sbomType string,
) (string, error) {
	return f.attest(ctx, dagger.Secret{}, dagger.Secret{}, registryUsername, registryPassword, dockerConfig, cosignImage, cosignUser, digest, predicate, sbomType)
}

// Clean will run cosign clean from the image, as defined by the cosignImage
// parameter, to clean the defined types of the given Container image digest
func (f *Cosign) Clean(
	ctx context.Context,
	// registry username
	//+optional
	registryUsername *string,
	// name of the image
	//+optional
	registryPassword *dagger.Secret,
	// Cosign container image
	//+optional
	//+default="chainguard/cosign:latest"
	cosignImage *string,
	// Cosign container image user
	//+optional
	//+default="nonroot"
	cosignUser *string,
	// Container image digest to clean
	digest string,
	// Clean type (signature|attestation|all)
	//+optional
	//+default="all"
	cleanType string,
) (string, error) {
	cmd := []string{"cosign", "clean", "--type", cleanType, digest, "--force"}
    if registryUsername != nil && registryPassword != nil {
        pwd, err := registryPassword.Plaintext(ctx)
        if err != nil {
            return "", err
        }

        cmd = append(
            cmd,
            "--registry-username",
            *registryUsername,
            "--registry-password",
            pwd,
        )
    }

    return dag.
        Container().
        From(*cosignImage).
        WithUser(*cosignUser).
        WithExec(cmd).
        Stdout(ctx)
}

func (f *Cosign) sign(
	ctx context.Context,
	// Cosign private key (omit for keyless)
	//+optional
	privateKey dagger.Secret,
	// Cosign password (will use random password if omitted)
	//+optional
	password dagger.Secret,
	// registry username
	//+optional
	registryUsername *string,
	// name of the image
	//+optional
	registryPassword *dagger.Secret,
	// Docker config
	//+optional
	dockerConfig *dagger.File,
	// Cosign container image
	//+optional
	//+default="chainguard/cosign:latest"
	cosignImage *string,
	// Cosign container image user
	//+optional
	//+default="nonroot"
	cosignUser *string,
	// Container image digest to sign
	digest string,
) (string, error) {
	cmd := []string{}
	userHome := fmt.Sprintf("/home/%s/", *cosignUser)
	if privateKey == (dagger.Secret{}) {
		cmd = []string{"sh", "-c", "COSIGN_EXPERIMENTAL=1", "cosign", "generate-key-pair", "--output-key-prefix", userHome + "cosign", "&&", "cosign", "sign", digest, "--key", userHome + "cosign.key"}
	} else {
		cmd = []string{"cosign", "sign", digest, "--key", "env://COSIGN_PRIVATE_KEY"}
	}
	stdout, err := f.exec(ctx, privateKey, password, registryUsername, registryPassword, dockerConfig, cosignImage, cosignUser, nil, cmd)
	if err != nil {
		return "", err
	}
	return stdout, nil
}

func (f *Cosign) attest(
	ctx context.Context,
	// Cosign private key (omit for keyless)
	//+optional
	privateKey dagger.Secret,
	// Cosign password (will use random password if omitted)
	//+optional
	password dagger.Secret,
	// registry username
	//+optional
	registryUsername *string,
	// name of the image
	//+optional
	registryPassword *dagger.Secret,
	// Docker config
	//+optional
	dockerConfig *dagger.File,
	// Cosign container image
	//+optional
	//+default="chainguard/cosign:latest"
	cosignImage *string,
	// Cosign container image user
	//+optional
	//+default="nonroot"
	cosignUser *string,
	// Container image digest to attest
	digest string,
	// SBOM file
	predicate *dagger.File,
	// SBOM type
	//+optional
	//+default="spdxjson"
	sbomType string,
) (string, error) {
	cmd := []string{}
	userHome := fmt.Sprintf("/home/%s/", *cosignUser)
	if privateKey == (dagger.Secret{}) {
		cmd = []string{"sh", "-c", "COSIGN_EXPERIMENTAL=1", "cosign", "generate-key-pair", "--output-key-prefix", userHome + "cosign", "&&", "cosign", "attest", "--type", sbomType, "--predicate", userHome + "sbom.json", digest, "--key", userHome + "cosign.key"}
	} else {
		cmd = []string{"cosign", "attest", "--type", sbomType, "--predicate", userHome + "sbom.json", digest, "--key", "env://COSIGN_PRIVATE_KEY"}
	}
	stdout, err := f.exec(ctx, privateKey, password, registryUsername, registryPassword, dockerConfig, cosignImage, cosignUser, predicate, cmd)
	if err != nil {
		return "", err
	}
	return stdout, nil
}

func (f *Cosign) exec(
	ctx context.Context,
	// Cosign private key (omit for keyless)
	//+optional
	privateKey dagger.Secret,
	// Cosign password (will use random password if omitted)
	//+optional
	password dagger.Secret,
	// registry username
	//+optional
	registryUsername *string,
	// name of the image
	//+optional
	registryPassword *dagger.Secret,
	// Docker config
	//+optional
	dockerConfig *dagger.File,
	// Cosign container image
	//+optional
	//+default="chainguard/cosign:latest"
	cosignImage *string,
	// Cosign container image user
	//+optional
	//+default="nonroot"
	cosignUser *string,
	// SBOM file
	//+optional
	predicate *dagger.File,
	// Command to be executed
	cmd []string,
) (string, error) {
	if registryUsername != nil && registryPassword != nil {
		pwd, err := registryPassword.Plaintext(ctx)
		if err != nil {
			return "", err
		}

		cmd = append(
			cmd,
			"--registry-username",
			*registryUsername,
			"--registry-password",
			pwd,
		)
	}

	cosign := dag.
		Container().
		From(*cosignImage).
		WithUser(*cosignUser).
		WithEnvVariable("COSIGN_YES", "true")

	if password == (dagger.Secret{}) {
		randomPassword := dag.SetSecret("password", fmt.Sprintf("%d", time.Now().UnixNano()))
		cosign = cosign.WithSecretVariable("COSIGN_PASSWORD", randomPassword)
	} else {
		cosign = cosign.WithSecretVariable("COSIGN_PASSWORD", &password)
	}
	if privateKey != (dagger.Secret{}) {
		cosign = cosign.WithSecretVariable("COSIGN_PRIVATE_KEY", &privateKey)
	}

	userHome := fmt.Sprintf("/home/%s/", *cosignUser)
	if dockerConfig != nil {
		cosign = cosign.WithMountedFile(
			userHome+".docker/config.json",
			dockerConfig,
			dagger.ContainerWithMountedFileOpts{Owner: *cosignUser})
	}
	if predicate != nil {
		cosign = cosign.WithMountedFile(
			userHome+"sbom.json",
			predicate,
			dagger.ContainerWithMountedFileOpts{Owner: *cosignUser})
	}
	return cosign.WithExec(cmd).Stdout(ctx)
}
