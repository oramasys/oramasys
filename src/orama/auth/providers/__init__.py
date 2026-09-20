"""Optional AuthProviders (feature-flagged)."""
from orama.auth.providers.bearer import BearerTokenProvider
from orama.auth.providers.bitchat_proximity import BitChatProximityProvider
from orama.auth.providers.buzz_nip98 import BuzzNostrProvider
from orama.auth.providers.firebase_shaped import FirebaseShapedProvider
from orama.auth.providers.google_oidc import GoogleOidcProvider
from orama.auth.providers.twitter_x import TwitterXOauthProvider

__all__ = [
    "BearerTokenProvider",
    "BitChatProximityProvider",
    "BuzzNostrProvider",
    "FirebaseShapedProvider",
    "GoogleOidcProvider",
    "TwitterXOauthProvider",
]
