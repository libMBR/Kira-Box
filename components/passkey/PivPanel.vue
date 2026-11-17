<template>
  <section class="pk-panel">
    <div class="pk-panel-head">
      <h2>PIV</h2>
      <button
        class="pk-btn pk-btn-secondary"
        :disabled="busy"
        @click="check"
      >
        Check PIV application
      </button>
    </div>
    <p class="pk-muted">
      Wrong PIN or PUK entries consume the device retry counter.
    </p>

    <div class="pk-block">
      <h3>Change PIN</h3>
      <div class="pk-form pk-form-grid">
        <input
          v-model="pinOld"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="Current PIN"
        >
        <input
          v-model="pinNew"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="New PIN"
        >
        <input
          v-model="pinConfirm"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="Confirm new PIN"
        >
        <button class="pk-btn" :disabled="busy" @click="change('pin')">
          Change PIN
        </button>
      </div>
    </div>

    <div class="pk-block">
      <h3>Change PUK</h3>
      <div class="pk-form pk-form-grid">
        <input
          v-model="pukOld"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="Current PUK"
        >
        <input
          v-model="pukNew"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="New PUK"
        >
        <input
          v-model="pukConfirm"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="Confirm new PUK"
        >
        <button class="pk-btn" :disabled="busy" @click="change('puk')">
          Change PUK
        </button>
      </div>
    </div>

    <div class="pk-block">
      <h3>Management key</h3>
      <p class="pk-muted">
        Authentication uses a 3DES challenge/response. The management key stays
        in memory for this page only and is never stored.
      </p>
      <div class="pk-form pk-form-grid">
        <input
          v-model="authPin"
          class="pk-input"
          type="password"
          autocomplete="off"
          placeholder="PIN (optional)"
        >
        <input
          v-model="managementKey"
          class="pk-input"
          type="password"
          autocomplete="off"
          placeholder="Management key (48 hex digits)"
        >
        <button class="pk-btn" :disabled="busy" @click="authenticate">
          Authenticate
        </button>
      </div>
      <p v-if="authError" class="pk-field-error">{{ authError }}</p>
      <p v-else-if="authStatus" class="pk-muted">{{ authStatus }}</p>

      <h3>Change management key</h3>
      <p class="pk-muted">
        The current management key entered above is used to authorize the
        change.
      </p>
      <div class="pk-form pk-form-grid">
        <input
          v-model="newManagementKey"
          class="pk-input"
          type="password"
          autocomplete="off"
          placeholder="New management key (48 hex digits)"
        >
        <input
          v-model="newManagementKeyConfirm"
          class="pk-input"
          type="password"
          autocomplete="off"
          placeholder="Confirm new management key"
        >
        <button class="pk-btn" :disabled="busy" @click="changeManagementKey">
          Change management key
        </button>
      </div>
      <p v-if="mkError" class="pk-field-error">{{ mkError }}</p>
    </div>

    <div class="pk-block">
      <h3>Certificates</h3>
      <div class="pk-inline">
        <label for="piv-cert-slot" class="pk-muted">Slot</label>
        <select
          id="piv-cert-slot"
          v-model="slot"
          class="pk-input pk-input-small"
        >
          <option v-for="item in slotOptions" :key="item.id" :value="item.id">
            {{ item.label }}
          </option>
        </select>
      </div>
      <div class="pk-actions">
        <button
          class="pk-btn pk-btn-secondary"
          :disabled="busy"
          @click="loadCertificate"
        >
          Read certificate
        </button>
        <button
          class="pk-btn pk-btn-secondary"
          :disabled="busy || !certificate"
          @click="exportCertificate"
        >
          Export DER
        </button>
        <button
          class="pk-btn pk-btn-danger"
          :disabled="busy"
          @click="deleteCertificate"
        >
          Delete certificate
        </button>
      </div>
      <p v-if="certStatus" class="pk-muted">{{ certStatus }}</p>
      <p v-if="certError" class="pk-field-error">{{ certError }}</p>

      <div class="pk-form pk-form-grid">
        <input
          ref="certInput"
          class="pk-input"
          type="file"
          accept=".der,.cer,.crt,.pem"
          @change="onCertificateFile"
        >
        <button
          class="pk-btn"
          :disabled="busy || !pendingCertificate"
          @click="importCertificate"
        >
          Import certificate
        </button>
      </div>
      <p v-if="certFileName" class="pk-muted">{{ certFileName }}</p>
      <p class="pk-muted">
        Accepts DER or PEM. Importing replaces the certificate in the selected
        slot and is authorized with the management key entered above.
      </p>
    </div>

    <div class="pk-block">
      <h3>Keys</h3>
      <div class="pk-inline">
        <label for="piv-key-algorithm" class="pk-muted">Algorithm</label>
        <select
          id="piv-key-algorithm"
          v-model="algorithm"
          class="pk-input"
        >
          <option value="rsa2048">RSA 2048</option>
          <option value="p256">ECC P-256</option>
          <option value="p384">ECC P-384</option>
        </select>
        <button class="pk-btn" :disabled="busy" @click="generateKey">
          Generate key on card
        </button>
      </div>
      <p class="pk-muted">
        Generating a key replaces the private key in the selected slot and
        invalidates its certificate. The management key entered above is used
        to authorize the operation.
      </p>
      <p v-if="keyStatus" class="pk-muted">{{ keyStatus }}</p>
      <p v-if="keyError" class="pk-field-error">{{ keyError }}</p>
      <p v-if="generated" class="pk-muted">
        Public key:
        <code class="pk-code">{{ generated.publicKey }}</code>
      </p>

      <h3>Import private key</h3>
      <div class="pk-form pk-form-grid">
        <input
          ref="keyInput"
          class="pk-input"
          type="file"
          accept=".pem,.key"
          @change="onKeyFile"
        >
        <button
          class="pk-btn"
          :disabled="busy || !pendingKey"
          @click="importKey"
        >
          Import private key
        </button>
      </div>
      <p v-if="keyFileName" class="pk-muted">{{ keyFileName }}</p>
      <p class="pk-muted">
        Unencrypted PEM private keys only: RSA 2048, P-256, or P-384. The key is
        sent to the device and is not kept in the browser.
      </p>
    </div>
  </section>
</template>

<script lang="ts" setup>
import { computed, ref, watch } from "vue";
import type { Notify, Runner } from "~/composables/usePasskeyDevice";
import {
  authenticatePivManagementKey,
  changePivManagementKey,
  changePivPin,
  decodePivCertificate,
  deletePivCertificate,
  generatePivKey,
  importPivPrivateKey,
  parsePivManagementKey,
  parsePivPrivateKey,
  PIV_ALGORITHMS,
  PIV_SLOTS,
  readPivCertificate,
  selectPiv,
  validatePivCertificate,
  verifyPivPin,
  writePivCertificate,
  type PivAlgorithm,
  type PivGeneratedKey,
  type PivPinKind,
  type PivPrivateKey,
  type PivSlot,
} from "~/utils/passkey/piv";

const props = defineProps<{
  run: Runner;
  busy: boolean;
  notify: Notify;
}>();

const slotOptions = Object.values(PIV_SLOTS);

const pinOld = ref("");
const pinNew = ref("");
const pinConfirm = ref("");
const pukOld = ref("");
const pukNew = ref("");
const pukConfirm = ref("");

const authPin = ref("");
const managementKey = ref("");
const authError = ref("");
const authStatus = ref("");
const newManagementKey = ref("");
const newManagementKeyConfirm = ref("");
const mkError = ref("");

const slot = ref<PivSlot>("9a");
const certificate = ref<Uint8Array | null>(null);
const certificateSlot = ref<PivSlot | null>(null);
const pendingCertificate = ref<Uint8Array | null>(null);
const certFileName = ref("");
const certStatus = ref("");
const certError = ref("");
const certInput = ref<HTMLInputElement | null>(null);

const algorithm = ref<PivAlgorithm>("p256");
const pendingKey = ref<PivPrivateKey | null>(null);
const keyFileName = ref("");
const keyStatus = ref("");
const keyError = ref("");
const keyInput = ref<HTMLInputElement | null>(null);
const generated = ref<PivGeneratedKey | null>(null);

const slotLabel = computed(() => PIV_SLOTS[slot.value].label);

watch(slot, () => {
  certificate.value = null;
  certificateSlot.value = null;
  certStatus.value = "";
  certError.value = "";
  generated.value = null;
  keyStatus.value = "";
  keyError.value = "";
});

function messageOf(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  return "Unexpected error.";
}

async function check(): Promise<void> {
  const ok = await props.run(async (send) => {
    await selectPiv(send);
    return true;
  });
  if (ok) props.notify("success", "The PIV application is available.");
}

async function change(kind: PivPinKind): Promise<void> {
  const oldPin = kind === "pin" ? pinOld.value : pukOld.value;
  const newPin = kind === "pin" ? pinNew.value : pukNew.value;
  const confirmation = kind === "pin" ? pinConfirm.value : pukConfirm.value;
  if (newPin !== confirmation) {
    props.notify("error", "The new value entries do not match.");
    return;
  }
  const ok = await props.run(async (send) => {
    await changePivPin(send, kind, oldPin, newPin);
    return true;
  });
  if (!ok) return;
  if (kind === "pin") {
    pinOld.value = newPin;
    pinNew.value = "";
    pinConfirm.value = "";
  } else {
    pukOld.value = newPin;
    pukNew.value = "";
    pukConfirm.value = "";
  }
  props.notify("success", `${kind.toUpperCase()} changed.`);
}

async function authenticate(): Promise<void> {
  authError.value = "";
  authStatus.value = "";
  let key: Uint8Array;
  try {
    key = parsePivManagementKey(managementKey.value);
  } catch (error) {
    authError.value = messageOf(error);
    return;
  }
  try {
    const ok = await props.run(
      async (send) => {
        if (authPin.value) await verifyPivPin(send, authPin.value);
        await authenticatePivManagementKey(send, key);
        return true;
      },
      { silent: true, rethrow: true },
    );
    if (!ok) {
      authError.value = "Connect a device first.";
      return;
    }
  } catch (error) {
    authError.value = messageOf(error);
    return;
  }
  authStatus.value = "The management key was verified.";
  props.notify("success", "The management key was verified.");
}

async function changeManagementKey(): Promise<void> {
  mkError.value = "";
  let current: Uint8Array;
  let next: Uint8Array;
  try {
    current = parsePivManagementKey(managementKey.value);
    next = parsePivManagementKey(newManagementKey.value);
  } catch (error) {
    mkError.value = messageOf(error);
    return;
  }
  if (next.length !== 24) {
    mkError.value =
      "The new management key must be 24 bytes (48 hex digits).";
    return;
  }
  if (
    newManagementKey.value.replace(/[\s:-]/g, "").toLowerCase() !==
    newManagementKeyConfirm.value.replace(/[\s:-]/g, "").toLowerCase()
  ) {
    mkError.value = "The new management key entries do not match.";
    return;
  }
  if (
    !window.confirm(
      "Change the PIV management key? The current page will keep using the new key.",
    )
  ) {
    return;
  }
  try {
    const ok = await props.run(
      async (send) => {
        await changePivManagementKey(send, current, next);
        return true;
      },
      { silent: true, rethrow: true },
    );
    if (!ok) {
      mkError.value = "Connect a device first.";
      return;
    }
  } catch (error) {
    mkError.value = messageOf(error);
    return;
  }
  managementKey.value = newManagementKey.value;
  newManagementKey.value = "";
  newManagementKeyConfirm.value = "";
  authStatus.value = "The management key was changed.";
  props.notify("success", "The management key was changed.");
}

async function loadCertificate(): Promise<void> {
  certError.value = "";
  certStatus.value = "";
  certificate.value = null;
  certificateSlot.value = null;
  try {
    const result = await props.run(
      async (send) => ({
        certificate: await readPivCertificate(send, slot.value),
      }),
      { silent: true, rethrow: true },
    );
    if (!result) {
      certError.value = "Connect a device first.";
      return;
    }
    if (!result.certificate) {
      certStatus.value = `No certificate is stored in ${slotLabel.value}.`;
      return;
    }
    certificate.value = result.certificate;
    certificateSlot.value = slot.value;
    certStatus.value = `Certificate found in ${slotLabel.value} (${result.certificate.length} bytes).`;
  } catch (error) {
    certError.value = messageOf(error);
  }
}

function exportCertificate(): void {
  const data = certificate.value;
  if (!data || certificateSlot.value !== slot.value) {
    certError.value = "Read the certificate before exporting it.";
    return;
  }
  const blob = new Blob([new Uint8Array(data)], {
    type: "application/pkix-cert",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `piv-${slot.value}-certificate.der`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function onCertificateFile(event: Event): Promise<void> {
  certError.value = "";
  certStatus.value = "";
  pendingCertificate.value = null;
  certFileName.value = "";
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  try {
    const decoded = decodePivCertificate(new Uint8Array(await file.arrayBuffer()));
    validatePivCertificate(decoded);
    pendingCertificate.value = decoded;
    certFileName.value = `${file.name} (${decoded.length} bytes)`;
  } catch (error) {
    certError.value = messageOf(error);
    input.value = "";
  }
}

async function importCertificate(): Promise<void> {
  certError.value = "";
  certStatus.value = "";
  const certificateToWrite = pendingCertificate.value;
  if (!certificateToWrite) {
    certError.value = "Choose a certificate file first.";
    return;
  }
  let key: Uint8Array;
  try {
    key = parsePivManagementKey(managementKey.value);
  } catch (error) {
    certError.value = messageOf(error);
    return;
  }
  if (
    !window.confirm(
      `Replace the certificate in ${slotLabel.value}? The existing certificate will be overwritten.`,
    )
  ) {
    return;
  }
  try {
    const ok = await props.run(
      async (send) => {
        await writePivCertificate(send, slot.value, certificateToWrite, key);
        return true;
      },
      { silent: true, rethrow: true },
    );
    if (!ok) {
      certError.value = "Connect a device first.";
      return;
    }
  } catch (error) {
    certError.value = messageOf(error);
    return;
  }
  certificate.value = certificateToWrite;
  certificateSlot.value = slot.value;
  certStatus.value = `Certificate imported into ${slotLabel.value} (${certificateToWrite.length} bytes).`;
  pendingCertificate.value = null;
  certFileName.value = "";
  if (certInput.value) certInput.value.value = "";
  props.notify("success", "Certificate imported.");
}

async function deleteCertificate(): Promise<void> {
  certError.value = "";
  certStatus.value = "";
  let key: Uint8Array;
  try {
    key = parsePivManagementKey(managementKey.value);
  } catch (error) {
    certError.value = messageOf(error);
    return;
  }
  if (
    !window.confirm(
      `Delete the certificate in ${slotLabel.value}? This cannot be undone.`,
    )
  ) {
    return;
  }
  try {
    const ok = await props.run(
      async (send) => {
        await deletePivCertificate(send, slot.value, key);
        return true;
      },
      { silent: true, rethrow: true },
    );
    if (!ok) {
      certError.value = "Connect a device first.";
      return;
    }
  } catch (error) {
    certError.value = messageOf(error);
    return;
  }
  certificate.value = null;
  certificateSlot.value = null;
  certStatus.value = `Certificate deleted from ${slotLabel.value}.`;
  props.notify("success", "Certificate deleted.");
}

async function generateKey(): Promise<void> {
  keyError.value = "";
  keyStatus.value = "";
  generated.value = null;
  let key: Uint8Array;
  try {
    key = parsePivManagementKey(managementKey.value);
  } catch (error) {
    keyError.value = messageOf(error);
    return;
  }
  const label = PIV_ALGORITHMS[algorithm.value].label;
  if (
    !window.confirm(
      `Generate a new ${label} key in ${slotLabel.value}? The existing private key and its certificate will no longer match.`,
    )
  ) {
    return;
  }
  try {
    const result = await props.run(
      (send) => generatePivKey(send, slot.value, algorithm.value, key),
      { silent: true, rethrow: true },
    );
    if (!result) {
      keyError.value = "Connect a device first.";
      return;
    }
    generated.value = result;
    certificate.value = null;
    certificateSlot.value = null;
    certStatus.value = "";
    certError.value = "";
    keyStatus.value = `Generated a ${label} key in ${slotLabel.value}. ${result.summary}.`;
  } catch (error) {
    keyError.value = messageOf(error);
    return;
  }
  props.notify("success", "Key generated.");
}

async function onKeyFile(event: Event): Promise<void> {
  keyError.value = "";
  keyStatus.value = "";
  pendingKey.value = null;
  keyFileName.value = "";
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  try {
    pendingKey.value = parsePivPrivateKey(await file.text());
    keyFileName.value = file.name;
  } catch (error) {
    keyError.value = messageOf(error);
    input.value = "";
  }
}

async function importKey(): Promise<void> {
  keyError.value = "";
  keyStatus.value = "";
  const keyToImport = pendingKey.value;
  if (!keyToImport) {
    keyError.value = "Choose a PEM private key file first.";
    return;
  }
  let key: Uint8Array;
  try {
    key = parsePivManagementKey(managementKey.value);
  } catch (error) {
    keyError.value = messageOf(error);
    return;
  }
  const label =
    keyToImport.kind === "rsa"
      ? "RSA 2048"
      : keyToImport.curve === "p256"
        ? "P-256"
        : "P-384";
  if (
    !window.confirm(
      `Import this ${label} private key into ${slotLabel.value}? The existing private key will be replaced.`,
    )
  ) {
    return;
  }
  try {
    const ok = await props.run(
      async (send) => {
        await importPivPrivateKey(send, slot.value, keyToImport, key);
        return true;
      },
      { silent: true, rethrow: true },
    );
    if (!ok) {
      keyError.value = "Connect a device first.";
      return;
    }
  } catch (error) {
    keyError.value = messageOf(error);
    return;
  }
  keyStatus.value = `Imported a ${label} private key into ${slotLabel.value}.`;
  certificate.value = null;
  certificateSlot.value = null;
  certStatus.value = "";
  certError.value = "";
  pendingKey.value = null;
  keyFileName.value = "";
  if (keyInput.value) keyInput.value.value = "";
  props.notify("success", "Private key imported.");
}
</script>
