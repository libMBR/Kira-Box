import { ref } from "vue";
import type { DeviceConfig } from "~/utils/passkey/device";
import type { OathCredential, OathState } from "~/utils/passkey/oath";
import type { OpenPgpCard } from "~/utils/passkey/openpgp";

export interface OathCache {
  state: OathState;
  credentials: OathCredential[];
}

const deviceConfig = ref<DeviceConfig | null>(null);
const oath = ref<OathCache | null>(null);
const openPgp = ref<OpenPgpCard | null>(null);

export function usePasskeyCache() {
  return { deviceConfig, oath, openPgp };
}

export function clearPasskeyCache(): void {
  deviceConfig.value = null;
  oath.value = null;
  openPgp.value = null;
}
