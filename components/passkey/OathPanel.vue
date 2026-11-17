<template>
  <section class="pk-panel">
    <div class="pk-panel-head">
      <h2>TOTP / HOTP</h2>
      <button class="pk-btn pk-btn-secondary" :disabled="busy" @click="refresh(false)">
        Refresh
      </button>
    </div>
    <p class="pk-muted pk-panel-description">
      Codes are generated on the key. The page refreshes at each 30-second
      boundary.
    </p>

    <div v-if="passwordRequired" class="pk-inner">
      <h3>OATH password required</h3>
      <p class="pk-muted">
        This device protects its credentials with an OATH password. The password
        is kept in memory only.
      </p>
      <div class="pk-inline">
        <input
          v-model="passwordInput"
          class="pk-input"
          type="password"
          autocomplete="new-password"
          placeholder="OATH password"
          @keyup.enter="submitPassword"
        >
        <button class="pk-btn" :disabled="busy" @click="submitPassword">
          Unlock
        </button>
      </div>
    </div>

    <div class="pk-results">
      <div v-if="!loaded" class="pk-placeholder">
        Credentials are not loaded.
      </div>
      <p v-else-if="credentials.length === 0" class="pk-muted">
        No credentials are stored on this device.
      </p>

      <table v-else class="pk-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Code</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(item, index) in credentials" :key="item.name">
            <td>{{ item.name }}</td>
            <td>{{ item.type.toUpperCase() }}</td>
            <td>
              <template v-if="passwordRequired">
                <span class="pk-code">—</span>
              </template>
              <template v-else-if="item.requireTouch && !item.code">
                <span class="pk-badge">Touch</span>
              </template>
              <template v-else>
                <span class="pk-code">{{ item.code || "—" }}</span>
                <span
                  v-if="item.code && item.type === 'totp'"
                  class="pk-muted pk-countdown"
                >
                  {{ remaining }}s
                </span>
              </template>
            </td>
            <td class="pk-table-actions">
              <button
                class="pk-link-btn"
                :disabled="busy || passwordRequired"
                @click="copyCode(item, index)"
              >
                Copy
              </button>
              <button
                v-if="item.type === 'hotp' || item.requireTouch"
                class="pk-link-btn"
                :disabled="busy || passwordRequired"
                @click="calculate(item, index)"
              >
                Generate
              </button>
              <button
                v-if="item.type === 'hotp'"
                class="pk-link-btn"
                :disabled="busy || passwordRequired"
                @click="makeDefault(item)"
              >
                Default
              </button>
              <button
                class="pk-link-btn pk-link-danger"
                :disabled="busy || passwordRequired"
                @click="remove(item)"
              >
                Delete
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <div v-if="!passwordRequired" class="pk-block">
        <h3>Add credential</h3>
        <div class="pk-inline pk-otpauth">
          <input
            v-model="otpauthInput"
            class="pk-input pk-otpauth-input"
            placeholder="otpauth://totp/Issuer:account?secret=...&issuer=Issuer"
            autocomplete="off"
            spellcheck="false"
            @input="otpauthError = ''"
            @keyup.enter="applyOtpauth"
          >
          <button
            class="pk-btn pk-btn-secondary"
            :disabled="busy || otpauthInput.trim().length === 0"
            @click="applyOtpauth"
          >
            Fill fields
          </button>
        </div>
        <p v-if="otpauthError" class="pk-field-error">{{ otpauthError }}</p>
        <p v-else class="pk-muted">
          Paste a Key URI to fill the fields below, or enter them manually.
          TOTP periods other than 30 seconds are rejected.
        </p>
        <div class="pk-form pk-form-grid">
          <input
            v-model="form.issuer"
            class="pk-input"
            placeholder="Issuer (optional)"
          >
          <input v-model="form.account" class="pk-input" placeholder="Account" >
          <input
            v-model="form.secret"
            class="pk-input"
            placeholder="Base32 secret"
            autocomplete="off"
          >
          <select v-model="form.type" class="pk-input">
            <option value="totp">TOTP</option>
            <option value="hotp">HOTP</option>
          </select>
          <select v-model="form.algorithm" class="pk-input">
            <option value="sha1">HMAC-SHA1</option>
            <option value="sha256">HMAC-SHA256</option>
          </select>
          <select v-model.number="form.digits" class="pk-input">
            <option :value="5">5 digits</option>
            <option :value="6">6 digits</option>
            <option :value="7">7 digits</option>
            <option :value="8">8 digits</option>
          </select>
          <input
            v-if="form.type === 'hotp'"
            v-model.number="form.counter"
            class="pk-input"
            type="number"
            min="0"
            placeholder="Initial counter"
          >
          <label v-if="form.type === 'totp'" class="pk-check">
            <input v-model="form.requireTouch" type="checkbox" >
            Require touch
          </label>
        </div>
        <p class="pk-muted">TOTP uses a fixed 30-second period.</p>
        <button class="pk-btn" :disabled="busy" @click="add">
          Add credential
        </button>
      </div>

      <div
        v-if="!passwordRequired && state?.protocol === 'v1'"
        class="pk-block"
      >
        <h3>OATH password</h3>
        <p class="pk-muted">
          Set a new password, or leave the field empty to remove it.
        </p>
        <div class="pk-inline">
          <input
            v-model="newPassword"
            class="pk-input"
            type="password"
            autocomplete="new-password"
            placeholder="New OATH password"
          >
          <button class="pk-btn" :disabled="busy" @click="changePassword">
            Save password
          </button>
        </div>
      </div>
    </div>
  </section>
</template>

<script lang="ts" setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from "vue";
import { usePasskeyCache } from "~/composables/usePasskeyCache";
import type { Notify, Runner } from "~/composables/usePasskeyDevice";
import { PasskeyError } from "~/utils/passkey/apdu";
import { decodeBase32 } from "~/utils/passkey/base32";
import {
  addOathCredential,
  calculateOathCode,
  deleteOathCredential,
  loadOathCredentials,
  selectOath,
  setDefaultOathCredential,
  setOathPassword,
  type OathAlgorithm,
  type OathCredential,
  type OathState,
  type OathType,
} from "~/utils/passkey/oath";
import { credentialName, parseOtpauthUri } from "~/utils/passkey/otpauth";

const props = defineProps<{
  run: Runner;
  busy: boolean;
  notify: Notify;
}>();

const { oath } = usePasskeyCache();
const credentials = ref<OathCredential[]>(oath.value?.credentials ?? []);
const state = ref<OathState | null>(oath.value?.state ?? null);
const loaded = ref(Boolean(oath.value));
const password = ref("");
const passwordInput = ref("");
const passwordRequired = ref(Boolean(oath.value?.state.requiresPassword));
const newPassword = ref("");
const now = ref(Date.now());
const otpauthInput = ref("");
const otpauthError = ref("");

const form = reactive({
  issuer: "",
  account: "",
  secret: "",
  type: "totp" as OathType,
  algorithm: "sha1" as OathAlgorithm,
  digits: 6,
  counter: 0,
  requireTouch: false,
});

const remaining = computed(() => 30 - (Math.floor(now.value / 1000) % 30));

let clockTimer: ReturnType<typeof setInterval> | null = null;
let refreshTimer: ReturnType<typeof setTimeout> | null = null;
let disposed = false;

function scheduleRefresh(delay = 0): void {
  if (disposed || passwordRequired.value) return;
  if (refreshTimer) clearTimeout(refreshTimer);
  const wait =
    delay > 0 ? delay : 30000 - (Date.now() % 30000) + 300;
  refreshTimer = setTimeout(async () => {
    if (disposed) return;
    if (props.busy) {
      scheduleRefresh(1000);
      return;
    }
    await refresh(true);
  }, wait);
}

async function refresh(silent: boolean): Promise<void> {
  if (disposed) return;
  const currentState = await props.run((send) => selectOath(send), { silent });
  if (!currentState) return;
  state.value = currentState;
  if (currentState.requiresPassword && password.value.length === 0) {
    passwordRequired.value = true;
    loaded.value = true;
    return;
  }
  passwordRequired.value = false;
  try {
    const result = await props.run(
      (send) => loadOathCredentials(send, password.value),
      { silent, rethrow: true },
    );
    if (result) {
      state.value = result.state;
      credentials.value = result.credentials;
      oath.value = {
        state: result.state,
        credentials: result.credentials,
      };
      loaded.value = true;
    }
  } catch (error) {
    loaded.value = true;
    if (
      currentState.requiresPassword &&
      error instanceof PasskeyError &&
      (error.code === "6982" || error.code?.startsWith("63C"))
    ) {
      password.value = "";
      passwordRequired.value = true;
    } else {
      scheduleRefresh();
    }
    return;
  }
  scheduleRefresh();
}

async function submitPassword(): Promise<void> {
  password.value = passwordInput.value;
  passwordInput.value = "";
  await refresh(false);
}

async function applyOtpauth(): Promise<void> {
  otpauthError.value = "";
  const raw = otpauthInput.value.trim();
  if (!raw) return;
  try {
    const parsed = parseOtpauthUri(raw);
    form.issuer = parsed.issuer;
    form.account = parsed.account;
    form.secret = parsed.secret;
    form.type = parsed.type;
    form.algorithm = parsed.algorithm;
    form.digits = parsed.digits;
    form.counter = parsed.counter;
    form.requireTouch = false;
  } catch (error) {
    otpauthError.value =
      error instanceof Error ? error.message : "Invalid otpauth URI.";
  }
}

async function add(): Promise<void> {
  let account = form.account.trim();
  let issuer = form.issuer.trim();
  let secret = form.secret.trim();
  if (/^otpauth:\/\//i.test(secret)) {
    try {
      const parsed = parseOtpauthUri(secret);
      issuer = parsed.issuer;
      account = parsed.account;
      secret = parsed.secret;
      form.issuer = parsed.issuer;
      form.account = parsed.account;
      form.secret = parsed.secret;
      form.type = parsed.type;
      form.algorithm = parsed.algorithm;
      form.digits = parsed.digits;
      form.counter = parsed.counter;
      otpauthError.value = "";
    } catch (error) {
      const text =
        error instanceof Error ? error.message : "Invalid otpauth URI.";
      otpauthError.value = text;
      props.notify("error", text);
      return;
    }
  }
  if (account.length === 0) {
    props.notify("error", "Enter an account name.");
    return;
  }
  const name = credentialName(issuer, account);
  if (new TextEncoder().encode(name).length > 64) {
    props.notify("error", "The name must be 1 to 64 UTF-8 bytes.");
    return;
  }
  let key: Uint8Array;
  try {
    key = decodeBase32(secret);
  } catch (error) {
    props.notify("error", error instanceof Error ? error.message : "Invalid secret.");
    return;
  }
  if (key.length > 32) {
    props.notify("error", "The secret must be at most 32 bytes.");
    return;
  }
  const ok = await props.run(async (send) => {
    await addOathCredential(send, password.value, {
      name,
      key,
      type: form.type,
      algorithm: form.algorithm,
      digits: form.digits,
      counter: form.counter,
      requireTouch: form.requireTouch,
    });
    return true;
  });
  if (ok) {
    form.secret = "";
    form.account = "";
    props.notify("success", "Credential added.");
    await refresh(false);
  }
}

async function calculate(item: OathCredential, index: number): Promise<void> {
  const result = await props.run(async (send) => {
    const code = await calculateOathCode(
      send,
      password.value,
      item.name,
      item.type,
    );
    return code;
  });
  if (result) {
    const target = credentials.value[index];
    if (target) target.code = result;
    props.notify("success", "Code generated.");
  }
}

async function copyCode(item: OathCredential, index: number): Promise<void> {
  let code = item.code;
  if (!code) {
    const result = await props.run(async (send) => {
      return calculateOathCode(send, password.value, item.name, item.type);
    });
    if (!result) return;
    code = result;
    const target = credentials.value[index];
    if (target) target.code = code;
  }
  try {
    await navigator.clipboard.writeText(code);
    props.notify("success", "Code copied.");
  } catch {
    props.notify("error", "The browser did not allow clipboard access.");
  }
}

async function makeDefault(item: OathCredential): Promise<void> {
  const ok = await props.run(async (send) => {
    await setDefaultOathCredential(send, password.value, item.name);
    return true;
  });
  if (ok) props.notify("success", "Default HOTP credential updated.");
}

async function remove(item: OathCredential): Promise<void> {
  if (!window.confirm(`Delete "${item.name}"?`)) return;
  const ok = await props.run(async (send) => {
    await deleteOathCredential(send, password.value, item.name);
    return true;
  });
  if (ok) {
    props.notify("success", "Credential deleted.");
    await refresh(false);
  }
}

async function changePassword(): Promise<void> {
  const value = newPassword.value;
  const ok = await props.run(async (send) => {
    await setOathPassword(send, value);
    return true;
  });
  if (ok) {
    password.value = value;
    newPassword.value = "";
    props.notify("success", "OATH password updated.");
    await refresh(false);
  }
}

onMounted(() => {
  clockTimer = setInterval(() => {
    now.value = Date.now();
  }, 1000);
  void refresh(Boolean(oath.value));
});

onBeforeUnmount(() => {
  disposed = true;
  if (clockTimer) clearInterval(clockTimer);
  if (refreshTimer) clearTimeout(refreshTimer);
});
</script>

<style scoped>
.pk-otpauth {
  align-items: flex-start;
}

.pk-otpauth-input {
  flex: 1 1 320px;
  min-width: 0;
  font-family: Consolas, monospace;
}
</style>
