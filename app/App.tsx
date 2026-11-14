import { StatusBar } from "expo-status-bar";
import * as SecureStore from "expo-secure-store";
import React from "react";
import {
  ActivityIndicator,
  Alert,
  FlatList,
  Pressable,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";

type Screen = "pair" | "console" | "task" | "approvals" | "settings";

type Task = {
  id: string;
  name?: string;
  description?: string;
  goal?: string;
  status?: string;
  paused?: boolean;
  goals_total?: number;
  goals_met?: number;
  hard_requirement?: string;
  distinct_findings?: { total?: number; critical?: number; high?: number; medium?: number; low?: number };
};

type Approval = {
  id: number | string;
  task_id?: string;
  tool_name?: string;
  reason?: string;
  status?: string;
  tool_input?: unknown;
  created_at?: string;
};

type Intent = { id: string; state: string; summary: string };
type Progress = {
  task: Task;
  stats?: unknown;
  intents: Intent[];
  approvals: Approval[];
  summary?: { running_intents?: number; pending_approvals?: number };
};
type Overview = { tasks: Task[]; approvals: Approval[]; counts?: { tasks?: number; running?: number; approvals?: number } };
type Confirmation = { confirmation_id: string; summary: string; status?: string };

const COLORS = {
  bg: "#0b0f14",
  card: "#141a21",
  card2: "#1b2430",
  border: "#26303b",
  text: "#e6edf3",
  muted: "#8b949e",
  accent: "#3b82f6",
  green: "#22c55e",
  red: "#ef4444",
  yellow: "#eab308",
};

async function api<T>(base: string, token: string | null, path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(base + path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers ?? {}),
    },
  });
  const text = await res.text();
  const body = text ? JSON.parse(text) : {};
  if (!res.ok) {
    throw new Error(body?.error ?? `HTTP ${res.status}`);
  }
  return body as T;
}

declare const process: { env: Record<string, string | undefined> };
const DEFAULT_BASE = process.env.EXPO_PUBLIC_BFF_URL ?? "http://127.0.0.1:8788";

export default function App() {
  const [screen, setScreen] = React.useState<Screen>("pair");
  const [base, setBase] = React.useState(DEFAULT_BASE);
  const [token, setToken] = React.useState<string | null>(null);
  const [password, setPassword] = React.useState("");
  const [deviceName, setDeviceName] = React.useState("Xiaomi 15");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");

  const [overview, setOverview] = React.useState<Overview | null>(null);
  const [selectedTask, setSelectedTask] = React.useState<Task | null>(null);
  const [progress, setProgress] = React.useState<Progress | null>(null);
  const [approvals, setApprovals] = React.useState<Approval[]>([]);
  const [directive, setDirective] = React.useState("");
  const [conductorInput, setConductorInput] = React.useState("");
  const [conductorReply, setConductorReply] = React.useState("");
  const [confirmations, setConfirmations] = React.useState<Confirmation[]>([]);
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    (async () => {
      const savedBase = await SecureStore.getItemAsync("ryagent_base").catch(() => null);
      const savedToken = await SecureStore.getItemAsync("ryagent_token").catch(() => null);
      if (savedBase) setBase(savedBase);
      if (savedToken) {
        setToken(savedToken);
        setScreen("console");
      }
    })();
  }, []);

  async function pair() {
    setBusy(true);
    setError("");
    try {
      const r = await api<{ token: string; device_id: string }>(base, null, "/v1/auth/pair", {
        method: "POST",
        body: JSON.stringify({ password, device_name: deviceName }),
      });
      await SecureStore.setItemAsync("ryagent_base", base);
      await SecureStore.setItemAsync("ryagent_token", r.token);
      setToken(r.token);
      setPassword("");
      setScreen("console");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const loadOverview = React.useCallback(async () => {
    if (!token) return;
    try {
      const r = await api<Overview>(base, token, "/v1/overview");
      setOverview(r);
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [base, token]);

  const loadProgress = React.useCallback(
    async (task: Task) => {
      if (!token) return;
      try {
        const r = await api<Progress>(base, token, `/v1/tasks/${encodeURIComponent(task.id)}/progress`);
        setProgress(r);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    },
    [base, token],
  );

  const loadApprovals = React.useCallback(async () => {
    if (!token) return;
    try {
      const r = await api<{ approvals: Approval[] }>(base, token, "/v1/approvals");
      setApprovals(r.approvals ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [base, token]);

  React.useEffect(() => {
    if (screen === "console" && token) {
      void loadOverview();
      const t = setInterval(() => void loadOverview(), 5000);
      return () => clearInterval(t);
    }
    if (screen === "task" && token && selectedTask) {
      void loadProgress(selectedTask);
      const t = setInterval(() => void loadProgress(selectedTask), 5000);
      return () => clearInterval(t);
    }
    if (screen === "approvals" && token) {
      void loadApprovals();
      const t = setInterval(() => void loadApprovals(), 5000);
      return () => clearInterval(t);
    }
  }, [screen, token, selectedTask, loadOverview, loadProgress, loadApprovals]);

  async function decide(a: Approval, allow: boolean) {
    Alert.alert(
      allow ? "批准这次调用？" : "拒绝这次调用？",
      `${a.tool_name ?? "工具"} · ${a.reason ?? ""}`,
      [
        { text: "取消", style: "cancel" },
        {
          text: allow ? "批准" : "拒绝",
          style: allow ? "default" : "destructive",
          onPress: async () => {
            try {
              await api(base, token, `/v1/approvals/${a.id}/decide`, {
                method: "POST",
                body: JSON.stringify({ decision: allow ? "allowed" : "denied" }),
              });
              await loadApprovals();
              await loadOverview();
            } catch (e) {
              Alert.alert("失败", e instanceof Error ? e.message : String(e));
            }
          },
        },
      ],
    );
  }

  async function sendDirective() {
    if (!selectedTask || !directive.trim()) return;
    const text = directive.trim();
    Alert.alert("发送给任务主 Agent？", text, [
      { text: "取消", style: "cancel" },
      {
        text: "发送",
        onPress: async () => {
          try {
            await api(base, token, `/v1/tasks/${encodeURIComponent(selectedTask.id)}/directive`, {
              method: "POST",
              body: JSON.stringify({ message: text }),
            });
            setDirective("");
            await loadProgress(selectedTask);
          } catch (e) {
            Alert.alert("发送失败", e instanceof Error ? e.message : String(e));
          }
        },
      },
    ]);
  }

  async function controlTask(action: "pause" | "resume") {
    if (!selectedTask) return;
    Alert.alert(action === "pause" ? "暂停任务？" : "恢复任务？", selectedTask.name ?? selectedTask.description ?? "", [
      { text: "取消", style: "cancel" },
      {
        text: action === "pause" ? "暂停" : "恢复",
        onPress: async () => {
          try {
            await api(base, token, `/v1/tasks/${encodeURIComponent(selectedTask.id)}/control`, {
              method: "POST",
              body: JSON.stringify({ action }),
            });
            await loadProgress(selectedTask);
          } catch (e) {
            Alert.alert("失败", e instanceof Error ? e.message : String(e));
          }
        },
      },
    ]);
  }

  async function sendConductor() {
    if (!conductorInput.trim()) return;
    setLoading(true);
    setError("");
    setConductorReply("");
    setConfirmations([]);
    try {
      const r = await api<{ reply: string; confirmations?: Confirmation[] }>(base, token, "/v1/conductor/messages", {
        method: "POST",
        body: JSON.stringify({ message: conductorInput.trim() }),
      });
      setConductorReply(r.reply ?? "");
      setConfirmations(r.confirmations ?? []);
      setConductorInput("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  async function resolveConfirmation(c: Confirmation, approve: boolean) {
    try {
      await api(base, token, `/v1/confirmations/${c.confirmation_id}`, {
        method: "POST",
        body: JSON.stringify({ approve }),
      });
      setConfirmations((prev) => prev.filter((x) => x.confirmation_id !== c.confirmation_id));
      await loadOverview();
    } catch (e) {
      Alert.alert("失败", e instanceof Error ? e.message : String(e));
    }
  }

  async function logout() {
    await SecureStore.deleteItemAsync("ryagent_token").catch(() => undefined);
    setToken(null);
    setOverview(null);
    setScreen("pair");
  }

  if (screen === "pair") {
    return (
      <SafeAreaView style={styles.safe}>
        <StatusBar style="light" />
        <ScrollView contentContainerStyle={styles.pairWrap}>
          <Text style={styles.logo}>RyAgent</Text>
          <Text style={styles.sub}>个人 Agent 控制台</Text>
          <View style={styles.card}>
            <Text style={styles.label}>BFF 地址</Text>
            <TextInput style={styles.input} value={base} onChangeText={setBase} autoCapitalize="none" />
            <Text style={styles.label}>配对密码</Text>
            <TextInput style={styles.input} value={password} onChangeText={setPassword} secureTextEntry />
            <Text style={styles.label}>设备名</Text>
            <TextInput style={styles.input} value={deviceName} onChangeText={setDeviceName} />
            {error ? <Text style={styles.error}>{error}</Text> : null}
            <TouchableOpacity style={styles.primary} onPress={() => void pair()} disabled={busy}>
              {busy ? <ActivityIndicator color="#fff" /> : <Text style={styles.primaryText}>连接</Text>}
            </TouchableOpacity>
            <Text style={styles.hint}>BFF 通过 adb reverse 或局域网访问；生产环境请使用 HTTPS。</Text>
          </View>
        </ScrollView>
      </SafeAreaView>
    );
  }

  if (screen === "console") {
    return (
      <SafeAreaView style={styles.safe}>
        <StatusBar style="light" />
        <View style={styles.header}>
          <View>
            <Text style={styles.title}>主控台</Text>
            <Text style={styles.muted}>
              {overview?.counts?.running ?? 0} 运行 · {overview?.counts?.approvals ?? 0} 待审批 · {overview?.counts?.tasks ?? 0} 任务
            </Text>
          </View>
          <View style={styles.headerActions}>
            <TouchableOpacity style={styles.ghost} onPress={() => setScreen("approvals")}>
              <Text style={styles.ghostText}>审批</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.ghost} onPress={() => setScreen("settings")}>
              <Text style={styles.ghostText}>设置</Text>
            </TouchableOpacity>
          </View>
        </View>
        {error ? <Text style={styles.error}>{error}</Text> : null}
        <FlatList
          data={overview?.tasks ?? []}
          keyExtractor={(t) => t.id}
          contentContainerStyle={styles.list}
          ListEmptyComponent={<Text style={styles.muted}>暂无任务</Text>}
          renderItem={({ item }) => {
            const f = item.distinct_findings;
            return (
              <Pressable
                style={styles.card}
                onPress={() => {
                  setSelectedTask(item);
                  setProgress(null);
                  setScreen("task");
                }}
              >
                <View style={styles.rowBetween}>
                  <Text style={styles.taskTitle} numberOfLines={1}>
                    #{item.id} {item.name || item.description || "未命名任务"}
                  </Text>
                  <Text style={[styles.status, statusColor(item)]}>{item.paused ? "paused" : item.status ?? "?"}</Text>
                </View>
                <Text style={styles.muted} numberOfLines={2}>{item.description}</Text>
                <View style={styles.metrics}>
                  <Text style={styles.metric}>目标 {item.goals_met ?? 0}/{item.goals_total ?? 0}</Text>
                  <Text style={styles.metric}>发现 {f?.total ?? 0}</Text>
                  {(f?.critical ?? 0) > 0 ? <Text style={styles.metricRed}>严重 {f?.critical}</Text> : null}
                  {(f?.high ?? 0) > 0 ? <Text style={styles.metricYellow}>高危 {f?.high}</Text> : null}
                </View>
              </Pressable>
            );
          }}
        />
        <View style={styles.composer}>
          <TextInput
            style={styles.composerInput}
            placeholder="问进度、发指令，例如：看下 task 4 到哪了"
            placeholderTextColor={COLORS.muted}
            value={conductorInput}
            onChangeText={setConductorInput}
            multiline
          />
          <TouchableOpacity style={styles.send} onPress={() => void sendConductor()} disabled={loading}>
            {loading ? <ActivityIndicator color="#fff" /> : <Text style={styles.sendText}>发送</Text>}
          </TouchableOpacity>
        </View>
        {conductorReply ? (
          <View style={styles.replyBox}>
            <Text style={styles.reply}>{conductorReply}</Text>
            {confirmations.map((c) => (
              <View key={c.confirmation_id} style={styles.confirmCard}>
                <Text style={styles.confirmText}>{c.summary}</Text>
                <View style={styles.row}>
                  <TouchableOpacity style={styles.primarySmall} onPress={() => void resolveConfirmation(c, true)}>
                    <Text style={styles.primaryText}>确认</Text>
                  </TouchableOpacity>
                  <TouchableOpacity style={styles.ghostSmall} onPress={() => void resolveConfirmation(c, false)}>
                    <Text style={styles.ghostText}>取消</Text>
                  </TouchableOpacity>
                </View>
              </View>
            ))}
          </View>
        ) : null}
      </SafeAreaView>
    );
  }

  if (screen === "task") {
    const t = progress?.task ?? selectedTask;
    return (
      <SafeAreaView style={styles.safe}>
        <StatusBar style="light" />
        <View style={styles.header}>
          <TouchableOpacity style={styles.ghost} onPress={() => setScreen("console")}>
            <Text style={styles.ghostText}>返回</Text>
          </TouchableOpacity>
          <Text style={styles.title} numberOfLines={1}>#{t?.id}</Text>
          <View style={styles.headerActions}>
            <TouchableOpacity style={styles.ghost} onPress={() => void controlTask(t?.paused ? "resume" : "pause")}>
              <Text style={styles.ghostText}>{t?.paused ? "恢复" : "暂停"}</Text>
            </TouchableOpacity>
          </View>
        </View>
        <ScrollView contentContainerStyle={styles.list}>
          {error ? <Text style={styles.error}>{error}</Text> : null}
          <View style={styles.card}>
            <Text style={styles.taskTitle}>{t?.name || t?.description || "任务"}</Text>
            <Text style={styles.muted}>{t?.goal}</Text>
            <View style={styles.metrics}>
              <Text style={styles.metric}>状态 {t?.paused ? "paused" : t?.status ?? "?"}</Text>
              <Text style={styles.metric}>目标 {t?.goals_met ?? 0}/{t?.goals_total ?? 0}</Text>
              <Text style={styles.metric}>待审批 {progress?.approvals?.length ?? 0}</Text>
            </View>
          </View>
          {t?.hard_requirement ? (
            <View style={[styles.card, styles.warnCard]}>
              <Text style={styles.label}>硬性要求（只读）</Text>
              <Text style={styles.reply}>{t.hard_requirement}</Text>
            </View>
          ) : null}
          <Text style={styles.section}>当前方向</Text>
          {(progress?.intents ?? []).length === 0 ? <Text style={styles.muted}>暂无意图</Text> : null}
          {(progress?.intents ?? []).map((i) => (
            <View key={i.id} style={styles.card}>
              <View style={styles.rowBetween}>
                <Text style={styles.mono}>#{i.id}</Text>
                <Text style={[styles.status, i.state === "running" ? { color: COLORS.green } : { color: COLORS.muted }]}>{i.state}</Text>
              </View>
              <Text style={styles.reply}>{i.summary || "（无摘要）"}</Text>
            </View>
          ))}
          <Text style={styles.section}>待审批</Text>
          {(progress?.approvals ?? []).length === 0 ? <Text style={styles.muted}>暂无</Text> : null}
          {(progress?.approvals ?? []).map((a) => (
            <View key={String(a.id)} style={styles.card}>
              <Text style={styles.taskTitle}>{a.tool_name ?? "工具"} #{a.id}</Text>
              <Text style={styles.muted}>{a.reason}</Text>
              <View style={styles.row}>
                <TouchableOpacity style={styles.primarySmall} onPress={() => void decide(a, true)}>
                  <Text style={styles.primaryText}>允许</Text>
                </TouchableOpacity>
                <TouchableOpacity style={styles.dangerSmall} onPress={() => void decide(a, false)}>
                  <Text style={styles.primaryText}>拒绝</Text>
                </TouchableOpacity>
              </View>
            </View>
          ))}
        </ScrollView>
        <View style={styles.composer}>
          <TextInput
            style={styles.composerInput}
            placeholder="给任务主 Agent 发指令，例如：只测登录接口"
            placeholderTextColor={COLORS.muted}
            value={directive}
            onChangeText={setDirective}
            multiline
          />
          <TouchableOpacity style={styles.send} onPress={() => void sendDirective()}>
            <Text style={styles.sendText}>发送</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  if (screen === "approvals") {
    return (
      <SafeAreaView style={styles.safe}>
        <StatusBar style="light" />
        <View style={styles.header}>
          <TouchableOpacity style={styles.ghost} onPress={() => setScreen("console")}>
            <Text style={styles.ghostText}>返回</Text>
          </TouchableOpacity>
          <Text style={styles.title}>审批收件箱</Text>
          <View style={{ width: 48 }} />
        </View>
        <FlatList
          data={approvals}
          keyExtractor={(a) => String(a.id)}
          contentContainerStyle={styles.list}
          ListEmptyComponent={<Text style={styles.muted}>暂无待审批</Text>}
          renderItem={({ item }) => (
            <View style={styles.card}>
              <View style={styles.rowBetween}>
                <Text style={styles.taskTitle}>{item.tool_name ?? "工具"} #{item.id}</Text>
                <Text style={styles.mono}>task {item.task_id ?? "?"}</Text>
              </View>
              <Text style={styles.muted}>{item.reason}</Text>
              <View style={styles.row}>
                <TouchableOpacity style={styles.primarySmall} onPress={() => void decide(item, true)}>
                  <Text style={styles.primaryText}>允许</Text>
                </TouchableOpacity>
                <TouchableOpacity style={styles.dangerSmall} onPress={() => void decide(item, false)}>
                  <Text style={styles.primaryText}>拒绝</Text>
                </TouchableOpacity>
              </View>
            </View>
          )}
        />
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.safe}>
      <StatusBar style="light" />
      <View style={styles.header}>
        <TouchableOpacity style={styles.ghost} onPress={() => setScreen("console")}>
          <Text style={styles.ghostText}>返回</Text>
        </TouchableOpacity>
        <Text style={styles.title}>设置</Text>
        <View style={{ width: 48 }} />
      </View>
      <ScrollView contentContainerStyle={styles.list}>
        <View style={styles.card}>
          <Text style={styles.label}>BFF 地址</Text>
          <TextInput style={styles.input} value={base} onChangeText={setBase} autoCapitalize="none" />
          <Text style={styles.hint}>修改后需要重新配对。</Text>
        </View>
        <View style={styles.card}>
          <Text style={styles.label}>设备</Text>
          <Text style={styles.muted}>{token ? "已配对" : "未配对"}</Text>
          <TouchableOpacity style={styles.dangerSmall} onPress={() => void logout()}>
            <Text style={styles.primaryText}>断开并清除 token</Text>
          </TouchableOpacity>
        </View>
        <View style={styles.card}>
          <Text style={styles.label}>说明</Text>
          <Text style={styles.muted}>这是 P0：任务进度、审批、指令、主控台。通知与前台服务在下一阶段接入。</Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

function statusColor(t: Task) {
  if (t.paused) return { color: COLORS.yellow };
  if (t.status === "running") return { color: COLORS.green };
  if (t.status === "done") return { color: COLORS.accent };
  if (t.status === "failed" || t.status === "timeout") return { color: COLORS.red };
  return { color: COLORS.muted };
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: COLORS.bg },
  pairWrap: { flexGrow: 1, justifyContent: "center", padding: 20 },
  logo: { color: COLORS.text, fontSize: 34, fontWeight: "700", textAlign: "center" },
  sub: { color: COLORS.muted, textAlign: "center", marginTop: 6, marginBottom: 24 },
  header: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingHorizontal: 14, paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: COLORS.border },
  headerActions: { flexDirection: "row", gap: 8 },
  title: { color: COLORS.text, fontSize: 20, fontWeight: "700" },
  muted: { color: COLORS.muted, fontSize: 12, marginTop: 4 },
  list: { padding: 14, gap: 10, paddingBottom: 120 },
  card: { backgroundColor: COLORS.card, borderColor: COLORS.border, borderWidth: 1, borderRadius: 12, padding: 12, gap: 6 },
  warnCard: { borderColor: "#7c5a00", backgroundColor: "#1f1a0d" },
  rowBetween: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", gap: 8 },
  row: { flexDirection: "row", alignItems: "center", gap: 8, marginTop: 8 },
  taskTitle: { color: COLORS.text, fontSize: 15, fontWeight: "600", flexShrink: 1 },
  status: { fontSize: 11, fontWeight: "600", textTransform: "uppercase" },
  metrics: { flexDirection: "row", flexWrap: "wrap", gap: 12, marginTop: 8 },
  metric: { color: COLORS.muted, fontSize: 11 },
  metricRed: { color: COLORS.red, fontSize: 11 },
  metricYellow: { color: COLORS.yellow, fontSize: 11 },
  label: { color: COLORS.muted, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.6 },
  input: { backgroundColor: COLORS.card2, borderColor: COLORS.border, borderWidth: 1, borderRadius: 8, color: COLORS.text, paddingHorizontal: 10, paddingVertical: 8, marginTop: 6 },
  primary: { backgroundColor: COLORS.accent, borderRadius: 10, paddingVertical: 12, alignItems: "center", marginTop: 16 },
  primarySmall: { backgroundColor: COLORS.accent, borderRadius: 8, paddingHorizontal: 14, paddingVertical: 8 },
  dangerSmall: { backgroundColor: COLORS.red, borderRadius: 8, paddingHorizontal: 14, paddingVertical: 8, marginTop: 8, alignSelf: "flex-start" },
  primaryText: { color: "#fff", fontWeight: "600" },
  ghost: { borderColor: COLORS.border, borderWidth: 1, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 6 },
  ghostSmall: { borderColor: COLORS.border, borderWidth: 1, borderRadius: 8, paddingHorizontal: 14, paddingVertical: 8 },
  ghostText: { color: COLORS.text, fontSize: 12 },
  hint: { color: COLORS.muted, fontSize: 11, marginTop: 8 },
  error: { color: COLORS.red, fontSize: 12, paddingHorizontal: 14, paddingTop: 8 },
  section: { color: COLORS.muted, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.6, marginTop: 8 },
  mono: { color: COLORS.muted, fontSize: 11, fontFamily: "monospace" },
  reply: { color: COLORS.text, fontSize: 13, lineHeight: 19 },
  replyBox: { backgroundColor: COLORS.card, borderTopColor: COLORS.border, borderTopWidth: 1, padding: 12, maxHeight: 260 },
  confirmCard: { backgroundColor: COLORS.card2, borderRadius: 10, padding: 10, marginTop: 10, gap: 6 },
  confirmText: { color: COLORS.text, fontSize: 13 },
  composer: { flexDirection: "row", alignItems: "flex-end", gap: 8, padding: 10, borderTopWidth: 1, borderTopColor: COLORS.border, backgroundColor: COLORS.bg },
  composerInput: { flex: 1, maxHeight: 100, minHeight: 42, backgroundColor: COLORS.card, borderColor: COLORS.border, borderWidth: 1, borderRadius: 10, color: COLORS.text, paddingHorizontal: 12, paddingVertical: 10 },
  send: { backgroundColor: COLORS.accent, borderRadius: 10, paddingHorizontal: 16, paddingVertical: 12 },
  sendText: { color: "#fff", fontWeight: "600" },
});
