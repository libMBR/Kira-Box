import { readonly, ref } from "vue";

// Session-only flags. A full page reload recreates this module state, so
// dangerous features are off again by default.
const dfuEnabled = ref(false);

export function usePasskeyFeatures() {
  function enableDfuActions(): void {
    dfuEnabled.value = true;
  }

  function disableDfuActions(): void {
    dfuEnabled.value = false;
  }

  return {
    dfuEnabled: readonly(dfuEnabled),
    enableDfuActions,
    disableDfuActions,
  };
}
