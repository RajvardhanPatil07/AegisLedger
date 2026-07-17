import { UserManager, type UserManagerSettings } from "oidc-client-ts";

const settings: UserManagerSettings = {
  authority:
    import.meta.env.VITE_OIDC_ISSUER ?? "http://localhost:8080/realms/aegisledger",
  client_id: "aegisledger-console",
  redirect_uri: `${window.location.origin}/auth/callback`,
  post_logout_redirect_uri: window.location.origin,
  response_type: "code",
  scope: "openid",
  loadUserInfo: false,
  automaticSilentRenew: false,
  monitorSession: false,
};

export function createUserManager(): UserManager {
  return new UserManager(settings);
}
