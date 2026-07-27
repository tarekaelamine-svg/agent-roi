from .control_plane import (
    CachedControlPlaneClient,
    ControlPlaneClient,
    ControlPlaneError,
    ControlPlaneService,
    HMACPolicySigner,
    PolicyBundle,
    PolicyBundleCache,
    PolicySignatureError,
    SqliteControlPlaneStore,
    create_fastapi_app,
)
from .identity import (
    AuthenticationError,
    AuthorizationError,
    DynamicRBACAuthorizer,
    OIDCConfig,
    OIDCVerifier,
    Principal,
    RBACAuthorizer,
    RoleBinding,
    RoleDefinition,
    SCIMDirectory,
    SCIMGroup,
    SCIMUser,
    SqliteIdentityStore,
)
from .telemetry import (
    AzureLogAnalyticsSink,
    CloudEvent,
    CloudWatchLogsSink,
    CompositeEventSink,
    DatadogEventSink,
    ElasticEventSink,
    EventDeliveryError,
    HttpCloudEventSink,
    InMemoryEventSink,
    OpenTelemetrySink,
    SplunkHECSink,
    configure_otlp_sink,
)

__all__ = [name for name in globals() if not name.startswith("_")]


def __getattr__(name: str):
    if name == "EnterpriseSentinelRunner":
        from .runtime import EnterpriseSentinelRunner
        return EnterpriseSentinelRunner
    raise AttributeError(name)

from .postgres import PostgresControlPlaneStore, PostgresIdentityStore
from .outbox import (
    JsonHttpOutboxHandler,
    OutboxEvent,
    OutboxEventSink,
    OutboxStatus,
    OutboxWorker,
    PostgresOutboxStore,
    SqliteOutboxStore,
)
from .signers import (
    AWSKMSPolicySigner,
    AzureKeyVaultPolicySigner,
    ExternalSignerError,
    GCPKMSPolicySigner,
    PKCS11PolicySigner,
    VaultTransitPolicySigner,
)
from .workload_identity import (
    AccessTokenProvider,
    AzureManagedIdentityProvider,
    GCPMetadataIdentityProvider,
    OAuthClientCredentialsProvider,
    SPIFFEIdentityVerifier,
    WorkloadIdentityPolicy,
    WorkloadOIDCVerifier,
)

__all__ = [name for name in globals() if not name.startswith("_")]
