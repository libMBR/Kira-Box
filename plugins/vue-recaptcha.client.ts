import { defineNuxtPlugin } from "#app";
import { VueReCaptcha } from "vue-recaptcha-v3";

const PASSKEY_PATH = "/tools/passkeymanagement";

export default defineNuxtPlugin((nuxtApp) => {
  let installed = false;

  function install(): void {
    if (installed) return;
    installed = true;
    nuxtApp.vueApp.use(VueReCaptcha, {
      siteKey: "6LeVsgEVAAAAAD_cU1YjriNpXfUAKTaWLCA1MlE1",
      loaderOptions: {
        useRecaptchaNet: true,
        autoHideBadge: true,
        explicitRenderParameters: {
          badge: "bottomright",
        },
      },
    });
  }

  if (!window.location.pathname.startsWith(PASSKEY_PATH)) {
    install();
    return;
  }

  const removeHook = nuxtApp.$router.afterEach((to) => {
    if (to.path.startsWith(PASSKEY_PATH)) return;
    install();
    removeHook();
  });
});
