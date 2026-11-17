<template>
  <section class="pk-panel">
    <div class="pk-panel-head">
      <h2>OpenPGP</h2>
      <button class="pk-btn pk-btn-secondary" :disabled="busy" @click="load(false)">
        Refresh
      </button>
    </div>
    <p class="pk-muted pk-panel-description">
      Card information, PINs, keys, certificates, and touch policies.
    </p>

    <div v-if="!card" class="pk-placeholder pk-placeholder-tall">
      Card information is not loaded.
    </div>

    <template v-else>
      <h3>Card information</h3>
      <table class="pk-table pk-table-info">
        <tbody>
          <tr><th>Version</th><td>{{ card.version }}</td></tr>
          <tr><th>Manufacturer ID</th><td>{{ card.manufacturerId }}</td></tr>
          <tr><th>Serial number</th><td>{{ card.serialNumber }}</td></tr>
          <tr><th>Cardholder</th><td>{{ card.cardholder || "—" }}</td></tr>
          <tr><th>Public key URL</th><td>{{ card.publicKeyUrl || "—" }}</td></tr>
        </tbody>
      </table>

      <h3>Key fingerprints</h3>
      <table class="pk-table pk-table-info">
        <tbody>
          <tr><th>Signature</th><td class="pk-code">{{ card.fingerprints.signature }}</td></tr>
          <tr><th>Encryption</th><td class="pk-code">{{ card.fingerprints.encryption }}</td></tr>
          <tr><th>Authentication</th><td class="pk-code">{{ card.fingerprints.authentication }}</td></tr>
        </tbody>
      </table>

      <h3>Admin PIN</h3>
      <p class="pk-muted">
        Used for key, certificate, URL, touch-policy, and cache-time changes.
        Wrong entries consume the device retry counter. The PIN is not stored.
      </p>
      <input
        v-model="adminPin"
        class="pk-input pk-input-full"
        type="password"
        autocomplete="new-password"
        placeholder="Admin PIN"
        @input="clearAdminErrors"
      >
      <p v-if="adminPinError" class="pk-field-error">{{ adminPinError }}</p>

      <h3>Keys and certificates</h3>
      <p class="pk-muted">
        Generating or importing a key replaces the existing key in the selected
        slot. Importing a certificate replaces the stored certificate. Deleting
        a certificate cannot be undone.
      </p>
      <table class="pk-table">
        <thead>
          <tr>
            <th>Slot</th>
            <th>Algorithm</th>
            <th>Key</th>
            <th>Certificate</th>
            <th/>
          </tr>
        </thead>
        <tbody>
          <tr v-for="key in keyNames" :key="key">
            <th>{{ labelFor(key) }}</th>
            <td>{{ algorithmLabel(card.slots[key].algorithm) }}</td>
            <td>{{ keyStatusLabel(card.slots[key].key) }}</td>
            <td>{{ card.slots[key].certificate ? "Present" : "None" }}</td>
            <td class="pk-table-actions">
              <button
                class="pk-link-btn"
                :disabled="busy"
                @click="chooseSlot(key)"
              >
                Manage
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <div class="pk-inner">
        <h4>{{ labelFor(activeSlot) }} slot</h4>

        <h4>Generate key</h4>
        <p class="pk-muted">
          The key is created inside the card. Generation replaces the existing
          key in this slot.
        </p>
        <div class="pk-inline">
          <select v-model="generationAlgorithm" class="pk-input pk-input-small">
            <option
              v-for="value in OPENPGP_GENERATION_ALGORITHMS"
              :key="value"
              :value="value"
            >
              {{ algorithmLabel(value) }}
            </option>
          </select>
          <button class="pk-btn" :disabled="busy" @click="generateKey">
            Generate key
          </button>
        </div>
        <p v-if="generationError" class="pk-field-error">{{ generationError }}</p>

        <h4>Import private key</h4>
        <p class="pk-muted">
          PEM keys are read in the browser and sent directly to the card. For
          Curve25519 and secp256k1, enter the raw 32-byte private scalar as hex.
        </p>
        <div class="pk-inline">
          <select
            v-model="importAlgorithm"
            class="pk-input pk-input-small"
            @change="onImportAlgorithmChange"
          >
            <option
              v-for="value in OPENPGP_IMPORT_ALGORITHMS"
              :key="value"
              :value="value"
            >
              {{ algorithmLabel(value) }}
            </option>
          </select>
          <input
            v-if="!usesHexImport"
            class="pk-input"
            type="file"
            accept=".pem,.key"
            @change="readKeyFile"
          >
          <span v-if="keyFileName" class="pk-muted">{{ keyFileName }}</span>
          <button class="pk-btn" :disabled="busy" @click="importKey">
            Import key
          </button>
        </div>
        <textarea
          v-if="usesHexImport"
          v-model="keyHex"
          class="pk-input pk-input-full"
          rows="3"
          spellcheck="false"
          placeholder="Private scalar as hex"
          @input="importError = ''"
        />
        <p v-if="importError" class="pk-field-error">{{ importError }}</p>

        <h4>Certificate</h4>
        <p class="pk-muted">
          Certificates are stored as raw DER on the card. The card limit is
          1152 bytes.
        </p>
        <div class="pk-inline">
          <input
            class="pk-input"
            type="file"
            accept=".der,.cer,.crt,.pem"
            @change="readCertFile"
          >
          <button
            class="pk-btn"
            :disabled="busy || !certBytes"
            @click="importCertificate"
          >
            Import certificate
          </button>
          <button
            class="pk-btn pk-btn-secondary"
            :disabled="busy || !card.slots[activeSlot].certificate"
            @click="exportCertificate"
          >
            Download
          </button>
          <button
            class="pk-link-btn pk-link-danger"
            :disabled="busy || !card.slots[activeSlot].certificate"
            @click="deleteCertificate"
          >
            Delete
          </button>
        </div>
        <p v-if="certificateError" class="pk-field-error">
          {{ certificateError }}
        </p>
      </div>

      <h3>Public key URL</h3>
      <div class="pk-inline">
        <input
          v-model="urlValue"
          class="pk-input"
          type="url"
          placeholder="https://example.com/public-key"
          @input="urlError = ''"
        >
        <button class="pk-btn" :disabled="busy" @click="saveUrl">
          Save URL
        </button>
      </div>
      <p v-if="urlError" class="pk-field-error">{{ urlError }}</p>

      <h3>Change PIN</h3>
      <div class="pk-form pk-form-grid">
        <input
          v-model="userOld"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="Current user PIN"
        >
        <input
          v-model="userNew"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="New user PIN (6-64)"
        >
        <input
          v-model="userConfirm"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="Confirm new user PIN"
        >
        <button class="pk-btn" :disabled="busy" @click="changePin('user')">
          Change user PIN
        </button>
      </div>

      <h3>Change Admin PIN</h3>
      <div class="pk-form pk-form-grid">
        <input
          v-model="adminOld"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="Current Admin PIN"
        >
        <input
          v-model="adminNew"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="New Admin PIN (8-64)"
        >
        <input
          v-model="adminConfirm"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="Confirm new Admin PIN"
        >
        <button class="pk-btn" :disabled="busy" @click="changePin('admin')">
          Change Admin PIN
        </button>
      </div>

      <h3>Touch policies</h3>
      <p class="pk-muted">
        Changing a policy uses the Admin PIN entered above. Permanent policies
        cannot be changed afterwards.
      </p>
      <table class="pk-table">
        <tbody>
          <tr v-for="key in keyNames" :key="key">
            <th>{{ labelFor(key) }}</th>
            <td>
              <span v-if="card.policies[key] === 'unavailable'" class="pk-muted">
                Not supported
              </span>
              <template v-else>
                <select
                  v-model="selectedPolicy[key]"
                  class="pk-input pk-input-small"
                  :disabled="card.policies[key] === 'permanent'"
                >
                  <option value="off">Off</option>
                  <option value="on">On</option>
                  <option value="permanent">Permanent</option>
                </select>
                <button
                  class="pk-link-btn"
                  :disabled="busy || card.policies[key] === 'permanent'"
                  @click="applyPolicy(key)"
                >
                  Apply
                </button>
                <span v-if="card.policies[key] === 'permanent'" class="pk-muted">
                  Permanent
                </span>
              </template>
            </td>
          </tr>
        </tbody>
      </table>

      <h3>Touch cache time</h3>
      <p class="pk-muted">
        Current: {{ card.cacheTime === null ? "Not supported" : `${card.cacheTime}s` }}
      </p>
      <div class="pk-inline">
        <input
          v-model.number="cacheTime"
          class="pk-input pk-input-small"
          type="number"
          min="0"
          max="255"
          placeholder="0-255"
          @input="cacheError = ''"
        >
        <span class="pk-muted">seconds</span>
        <button class="pk-btn" :disabled="busy || card.cacheTime === null" @click="applyCache">
          Save cache time
        </button>
      </div>
      <p v-if="cacheError" class="pk-field-error">{{ cacheError }}</p>
    </template>
  </section>
</template>

<script lang="ts" setup>
import { computed, onMounted, reactive, ref } from "vue";
import { usePasskeyCache } from "~/composables/usePasskeyCache";
import type { Notify, Runner } from "~/composables/usePasskeyDevice";
import { decodePivCertificate } from "~/utils/passkey/piv";
import {
  algorithmLabel,
  changeOpenPgpPin,
  deleteOpenPgpCertificate,
  generateOpenPgpKey,
  importOpenPgpPrivateKey,
  OPENPGP_GENERATION_ALGORITHMS,
  OPENPGP_IMPORT_ALGORITHMS,
  readOpenPgpCard,
  readOpenPgpCertificate,
  setOpenPgpCacheTime,
  setOpenPgpUif,
  setOpenPgpUrl,
  writeOpenPgpCertificate,
  type OpenPgpAlgorithm,
  type OpenPgpCard,
  type OpenPgpKey,
  type OpenPgpKeyOperationResult,
  type OpenPgpKeyStatus,
  type OpenPgpSlotState,
  type TouchPolicy,
} from "~/utils/passkey/openpgp";

const props = defineProps<{
  run: Runner;
  busy: boolean;
  notify: Notify;
}>();

type SelectablePolicy = Exclude<TouchPolicy, "unavailable">;

const { openPgp } = usePasskeyCache();
const card = ref<OpenPgpCard | null>(openPgp.value);
const userOld = ref("");
const userNew = ref("");
const userConfirm = ref("");
const adminOld = ref("");
const adminNew = ref("");
const adminConfirm = ref("");
const adminPin = ref("");
const adminPinError = ref("");
const cacheError = ref("");
const cacheTime = ref(openPgp.value?.cacheTime ?? 0);
const activeSlot = ref<OpenPgpKey>("signature");
const generationAlgorithm = ref<OpenPgpAlgorithm>("p256");
const importAlgorithm = ref<OpenPgpAlgorithm>("p256");
const keyPem = ref("");
const keyHex = ref("");
const keyFileName = ref("");
const certBytes = ref<Uint8Array | null>(null);
const generationError = ref("");
const importError = ref("");
const certificateError = ref("");
const urlError = ref("");
const urlValue = ref(openPgp.value?.publicKeyUrl ?? "");
const selectedPolicy = reactive<Record<OpenPgpKey, SelectablePolicy>>({
  signature: "off",
  encryption: "off",
  authentication: "off",
});

const keyNames: OpenPgpKey[] = ["signature", "encryption", "authentication"];
const usesHexImport = computed(
  () =>
    importAlgorithm.value === "curve25519" ||
    importAlgorithm.value === "secp256k1",
);

function labelFor(key: OpenPgpKey): string {
  if (key === "signature") return "Signature";
  if (key === "encryption") return "Encryption";
  return "Authentication";
}

function keyStatusLabel(status: OpenPgpKeyStatus): string {
  if (status === "missing") return "None";
  if (status === "generated") return "Generated on card";
  if (status === "imported") return "Imported";
  return "Unknown";
}

function syncAlgorithm(): void {
  const current = card.value?.slots?.[activeSlot.value]?.algorithm ?? null;
  generationAlgorithm.value =
    current && OPENPGP_GENERATION_ALGORITHMS.includes(current)
      ? current
      : "p256";
  importAlgorithm.value = current ?? "p256";
}

function clearAdminErrors(): void {
  adminPinError.value = "";
  cacheError.value = "";
  urlError.value = "";
  generationError.value = "";
  importError.value = "";
  certificateError.value = "";
}

function applyCard(result: OpenPgpCard): void {
  const slots: Record<OpenPgpKey, OpenPgpSlotState> = result.slots ?? {
    signature: { algorithm: null, key: "unknown", certificate: false },
    encryption: { algorithm: null, key: "unknown", certificate: false },
    authentication: { algorithm: null, key: "unknown", certificate: false },
  };
  const normalized: OpenPgpCard = { ...result, slots };
  card.value = normalized;
  openPgp.value = normalized;
  if (result.cacheTime !== null) cacheTime.value = result.cacheTime;
  for (const key of keyNames) {
    const policy = result.policies[key];
    selectedPolicy[key] = policy === "unavailable" ? "off" : policy;
  }
  urlValue.value = result.publicKeyUrl;
  syncAlgorithm();
}

async function load(silent = false): Promise<void> {
  const result = await props.run((send) => readOpenPgpCard(send), { silent });
  if (result) applyCard(result);
}

async function changePin(kind: "user" | "admin"): Promise<void> {
  const oldPin = kind === "user" ? userOld.value : adminOld.value;
  const newPin = kind === "user" ? userNew.value : adminNew.value;
  const confirmation =
    kind === "user" ? userConfirm.value : adminConfirm.value;
  const minimum = kind === "admin" ? 8 : 6;
  if (newPin.length < minimum || newPin.length > 64) {
    props.notify("error", `The new PIN must be ${minimum} to 64 characters.`);
    return;
  }
  if (newPin !== confirmation) {
    props.notify("error", "The new PIN entries do not match.");
    return;
  }
  const ok = await props.run(async (send) => {
    await changeOpenPgpPin(send, kind, oldPin, newPin);
    return true;
  });
  if (!ok) return;
  if (kind === "user") {
    userOld.value = newPin;
    userNew.value = "";
    userConfirm.value = "";
  } else {
    adminOld.value = newPin;
    adminNew.value = "";
    adminConfirm.value = "";
  }
  props.notify("success", "PIN changed.");
}

function chooseSlot(key: OpenPgpKey): void {
  activeSlot.value = key;
  keyPem.value = "";
  keyHex.value = "";
  keyFileName.value = "";
  certBytes.value = null;
  generationError.value = "";
  importError.value = "";
  certificateError.value = "";
  const algorithm = card.value?.slots[key]?.algorithm ?? null;
  generationAlgorithm.value =
    algorithm && OPENPGP_GENERATION_ALGORITHMS.includes(algorithm)
      ? algorithm
      : "p256";
  importAlgorithm.value = algorithm ?? "p256";
}

function onImportAlgorithmChange(): void {
  keyPem.value = "";
  keyHex.value = "";
  keyFileName.value = "";
  importError.value = "";
}

function keyResultMessage(
  prefix: string,
  result: OpenPgpKeyOperationResult,
): string {
  const fingerprint = result.fingerprint
    ? ` Fingerprint: ${result.fingerprint}.`
    : "";
  const metadata = result.metadataStored
    ? ""
    : " The fingerprint could not be stored on the card.";
  return `${prefix}${fingerprint}${metadata}`;
}

async function readKeyFile(event: Event): Promise<void> {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  importError.value = "";
  keyPem.value = "";
  keyFileName.value = "";
  if (!file) return;
  try {
    keyPem.value = await file.text();
    keyFileName.value = file.name;
  } catch {
    importError.value = "The selected key file could not be read.";
  }
}

async function readCertFile(event: Event): Promise<void> {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  certificateError.value = "";
  certBytes.value = null;
  if (!file) return;
  try {
    certBytes.value = decodePivCertificate(
      new Uint8Array(await file.arrayBuffer()),
    );
  } catch {
    certificateError.value = "The selected certificate file could not be read.";
  }
}

async function generateKey(): Promise<void> {
  generationError.value = "";
  if (adminPin.value.length === 0) {
    generationError.value = "Enter the Admin PIN first.";
    return;
  }
  const confirmed = window.confirm(
    `Generate a new ${labelFor(activeSlot.value).toLowerCase()} key? This replaces the existing key and may invalidate its certificate.`,
  );
  if (!confirmed) return;
  try {
    const result = await props.run(
      (send) =>
        generateOpenPgpKey(
          send,
          activeSlot.value,
          generationAlgorithm.value,
          adminPin.value,
        ),
      { silent: true, rethrow: true },
    );
    if (!result) return;
    props.notify("success", keyResultMessage("Key generated.", result));
    keyPem.value = "";
    keyHex.value = "";
    keyFileName.value = "";
    await load(true);
  } catch (error) {
    generationError.value =
      error instanceof Error ? error.message : "Unable to generate the key.";
  }
}

async function importKey(): Promise<void> {
  importError.value = "";
  if (adminPin.value.length === 0) {
    importError.value = "Enter the Admin PIN first.";
    return;
  }
  if (usesHexImport.value && keyHex.value.trim().length === 0) {
    importError.value = "Enter the private key as hexadecimal data.";
    return;
  }
  if (!usesHexImport.value && keyPem.value.trim().length === 0) {
    importError.value = "Choose a PEM private key file.";
    return;
  }
  const confirmed = window.confirm(
    `Import a private key into the ${labelFor(activeSlot.value).toLowerCase()} slot? This replaces the existing key.`,
  );
  if (!confirmed) return;
  try {
    const result = await props.run(
      (send) =>
        importOpenPgpPrivateKey(
          send,
          activeSlot.value,
          importAlgorithm.value,
          { pem: keyPem.value, hex: keyHex.value },
          adminPin.value,
        ),
      { silent: true, rethrow: true },
    );
    if (!result) return;
    props.notify("success", keyResultMessage("Private key imported.", result));
    keyPem.value = "";
    keyHex.value = "";
    keyFileName.value = "";
    await load(true);
  } catch (error) {
    importError.value =
      error instanceof Error ? error.message : "Unable to import the key.";
  }
}

async function importCertificate(): Promise<void> {
  certificateError.value = "";
  if (adminPin.value.length === 0) {
    certificateError.value = "Enter the Admin PIN first.";
    return;
  }
  const certificate = certBytes.value;
  if (!certificate) {
    certificateError.value = "Choose a DER certificate file first.";
    return;
  }
  const confirmed = window.confirm(
    `Import a certificate into the ${labelFor(activeSlot.value).toLowerCase()} slot? This replaces the stored certificate.`,
  );
  if (!confirmed) return;
  try {
    await props.run(
      async (send) => {
        await writeOpenPgpCertificate(
          send,
          activeSlot.value,
          certificate,
          adminPin.value,
        );
        return true;
      },
      { silent: true, rethrow: true },
    );
    props.notify("success", "Certificate imported.");
    certBytes.value = null;
    await load(true);
  } catch (error) {
    certificateError.value =
      error instanceof Error ? error.message : "Unable to import the certificate.";
  }
}

async function exportCertificate(): Promise<void> {
  certificateError.value = "";
  try {
    const certificate = await props.run(
      (send) => readOpenPgpCertificate(send, activeSlot.value),
      { silent: true, rethrow: true },
    );
    if (!certificate) {
      certificateError.value = "No certificate is stored in this slot.";
      return;
    }
    downloadFile(
      `openpgp-${activeSlot.value}-certificate.der`,
      certificate,
      "application/pkix-cert",
    );
    props.notify("success", "Certificate downloaded.");
  } catch (error) {
    certificateError.value =
      error instanceof Error ? error.message : "Unable to read the certificate.";
  }
}

async function deleteCertificate(): Promise<void> {
  certificateError.value = "";
  if (adminPin.value.length === 0) {
    certificateError.value = "Enter the Admin PIN first.";
    return;
  }
  const confirmed = window.confirm(
    `Delete the ${labelFor(activeSlot.value).toLowerCase()} certificate? This cannot be undone.`,
  );
  if (!confirmed) return;
  try {
    await props.run(
      async (send) => {
        await deleteOpenPgpCertificate(send, activeSlot.value, adminPin.value);
        return true;
      },
      { silent: true, rethrow: true },
    );
    props.notify("success", "Certificate deleted.");
    await load(true);
  } catch (error) {
    certificateError.value =
      error instanceof Error ? error.message : "Unable to delete the certificate.";
  }
}

async function saveUrl(): Promise<void> {
  urlError.value = "";
  if (adminPin.value.length === 0) {
    urlError.value = "Enter the Admin PIN first.";
    return;
  }
  try {
    await props.run(
      async (send) => {
        await setOpenPgpUrl(send, urlValue.value, adminPin.value);
        return true;
      },
      { silent: true, rethrow: true },
    );
    props.notify("success", "Public key URL updated.");
    await load(true);
  } catch (error) {
    urlError.value =
      error instanceof Error ? error.message : "Unable to update the URL.";
  }
}

function downloadFile(name: string, data: Uint8Array, type: string): void {
  const blob = new Blob([data.slice()], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

async function applyPolicy(key: OpenPgpKey): Promise<void> {
  adminPinError.value = "";
  if (adminPin.value.length === 0) {
    adminPinError.value = "Enter the Admin PIN first.";
    return;
  }
  const policy = selectedPolicy[key];
  if (policy === "permanent") {
    const confirmed = window.confirm(
      "A permanent policy cannot be changed afterwards. Continue?",
    );
    if (!confirmed) return;
  }
  try {
    await props.run(
      async (send) => {
        await setOpenPgpUif(send, key, policy, adminPin.value);
        return true;
      },
      { silent: true, rethrow: true },
    );
    props.notify("success", "Touch policy updated.");
    await load(true);
  } catch (error) {
    adminPinError.value =
      error instanceof Error ? error.message : "Unable to update the policy.";
  }
}

async function applyCache(): Promise<void> {
  adminPinError.value = "";
  cacheError.value = "";
  if (adminPin.value.length === 0) {
    adminPinError.value = "Enter the Admin PIN first.";
    return;
  }
  const seconds = cacheTime.value;
  if (!Number.isInteger(seconds) || seconds < 0 || seconds > 255) {
    cacheError.value = "Cache time must be between 0 and 255 seconds.";
    return;
  }
  try {
    await props.run(
      async (send) => {
        await setOpenPgpCacheTime(send, seconds, adminPin.value);
        return true;
      },
      { silent: true, rethrow: true },
    );
    props.notify("success", "Touch cache time updated.");
    await load(true);
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unable to update cache time.";
    if (/pin|verification|locked/i.test(message)) {
      adminPinError.value = message;
    } else {
      cacheError.value = message;
    }
  }
}

if (openPgp.value) applyCard(openPgp.value);

onMounted(() => {
  void load(Boolean(openPgp.value));
});
</script>
