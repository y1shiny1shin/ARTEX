"use client";

import * as React from "react";

import { Loader2Icon, PencilIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { localizedError } from "@/i18n/errors";
import { useLiveTranslation } from "@/i18n/use-live-translation";
import { api } from "@/lib/api";
import type { ProxySource } from "@/lib/types";

// ProxySourcesCard manages the hunter's discovery sources. It deliberately ships
// with NO built-in public list: the operator adds a FOFA API source or an HTTP
// list URL. Credentials are write-only from this UI (the server never returns
// them); the hunter reads them by source id.
export function ProxySourcesCard() {
  const { t } = useLiveTranslation();
  const [sources, setSources] = React.useState<ProxySource[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [editingID, setEditingID] = React.useState<number | null>(null);
  const [name, setName] = React.useState("");
  const [kind, setKind] = React.useState<"http_list" | "fofa" | "hunter">("http_list");
  const [url, setURL] = React.useState("");
  const [query, setQuery] = React.useState("");
  const [pages, setPages] = React.useState("1");
  const [email, setEmail] = React.useState("");
  const [key, setKey] = React.useState("");
  const [enabled, setEnabled] = React.useState(true);

  const load = React.useCallback(async () => {
    try {
      setSources(await api.proxySources());
    } catch (e) {
      toast.error(localizedError(e, t));
    } finally {
      setLoading(false);
    }
  }, [t]);

  React.useEffect(() => {
    void load();
  }, [load]);

  function reset() {
    setEditingID(null);
    setName("");
    setKind("http_list");
    setURL("");
    setQuery("");
    setPages("1");
    setEmail("");
    setKey("");
    setEnabled(true);
  }

  function startEdit(src: ProxySource) {
    setEditingID(src.id);
    setName(src.name);
    setKind(src.kind);
    setURL(src.url);
    setQuery(src.query);
    setPages(String(src.pages || 1));
    setEmail("");
    setKey("");
    setEnabled(src.enabled);
  }

  async function save() {
    if (
      !name.trim() ||
      (kind === "http_list" && !url.trim()) ||
      (kind === "fofa" && editingID === null && (!email.trim() || !key.trim())) ||
      (kind === "hunter" && editingID === null && !key.trim())
    ) {
      toast.error(t("settings.proxySourceRequired"));
      return;
    }
    setBusy(true);
    try {
      const payload = {
        name: name.trim(),
        kind,
        url: url.trim(),
        query: query.trim(),
        email: email.trim(),
        key: key.trim(),
        pages: Math.max(1, Math.min(10, Number(pages) || 1)),
        enabled,
      };
      if (editingID === null) {
        await api.createProxySource(payload);
      } else {
        await api.updateProxySource(editingID, payload);
      }
      toast.success(t("settings.proxySourceSaved"));
      reset();
      await load();
    } catch (e) {
      toast.error(localizedError(e, t));
    } finally {
      setBusy(false);
    }
  }

  async function remove(src: ProxySource) {
    if (!window.confirm(t("settings.proxySourceDeleteConfirm", { name: src.name }))) return;
    try {
      await api.deleteProxySource(src.id);
      toast.success(t("settings.proxySourceDeleted"));
      if (editingID === src.id) reset();
      await load();
    } catch (e) {
      toast.error(localizedError(e, t));
    }
  }

  const statusClass = (status: ProxySource["last_status"]) =>
    status === "ok" ? "text-emerald-600 dark:text-emerald-400" : status === "error" ? "text-destructive" : "text-muted-foreground";

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <PlusIcon className="size-4" /> {t("settings.proxySources")}
        </CardTitle>
        <CardDescription>{t("settings.proxySourcesHelp")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {loading ? (
          <div className="text-muted-foreground flex items-center gap-2 text-xs">
            <Loader2Icon className="size-3.5 animate-spin" /> ...
          </div>
        ) : sources.length === 0 ? (
          <p className="text-muted-foreground text-xs">{t("settings.proxySourceEmpty")}</p>
        ) : (
          <div className="flex flex-col gap-2">
            {sources.map((src) => (
              <div key={src.id} className="rounded-md border p-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium">{src.name}</span>
                  <Badge variant="outline">
                    {src.kind === "fofa"
                      ? t("settings.proxySourceFofa")
                      : src.kind === "hunter"
                        ? t("settings.proxySourceHunter")
                        : t("settings.proxySourceHttp")}
                  </Badge>
                  {src.kind === "fofa" && src.has_credentials ? (
                    <Badge variant="secondary">{t("settings.proxySourceCredsSet")}</Badge>
                  ) : null}
                  {!src.enabled ? <Badge variant="outline">off</Badge> : null}
                  <div className="ml-auto flex items-center gap-1">
                    <Button size="icon" variant="ghost" onClick={() => startEdit(src)} title={t("settings.proxySourceEdit")}>
                      <PencilIcon className="size-3.5" />
                    </Button>
                    <Button size="icon" variant="ghost" onClick={() => void remove(src)} title={t("settings.proxySourceDelete")}>
                      <Trash2Icon className="size-3.5" />
                    </Button>
                  </div>
                </div>
                <p className="text-muted-foreground mt-1 truncate text-xs">
                  {src.kind === "http_list" ? src.url : src.query || (src.kind === "hunter" ? "protocol=\"socks5\" && banner=\"No Authentication\"" : "protocol==\"socks5\" && ...")}
                </p>
                {(src.last_status || src.last_run_at) && (
                  <p className={`mt-1 text-xs ${statusClass(src.last_status)}`}>
                    {t("settings.proxySourceLastRun")}: {src.last_run_at ? new Date(src.last_run_at).toLocaleString() : "-"} · {src.last_status || "-"}
                    {src.last_error ? ` · ${src.last_error}` : ""}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}

        <div className="grid gap-3 border-t pt-3">
          <div className="text-sm font-medium">
            {editingID === null ? t("settings.proxySourceAdd") : t("settings.proxySourceEdit")}
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label htmlFor="proxy-source-name">{t("settings.proxySourceName")}</Label>
              <Input id="proxy-source-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="grid gap-1.5">
              <Label>{t("settings.proxySourceKind")}</Label>
              <Select value={kind} onValueChange={(v) => setKind(v as "http_list" | "fofa" | "hunter")}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="http_list">{t("settings.proxySourceHttp")}</SelectItem>
                  <SelectItem value="fofa">{t("settings.proxySourceFofa")}</SelectItem>
                  <SelectItem value="hunter">{t("settings.proxySourceHunter")}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          {kind === "http_list" ? (
            <div className="grid gap-1.5">
              <Label htmlFor="proxy-source-url">{t("settings.proxySourceURL")}</Label>
              <Input id="proxy-source-url" value={url} onChange={(e) => setURL(e.target.value)} placeholder="https://example.com/proxies.txt" />
            </div>
          ) : (
            <>
              <div className="grid gap-1.5">
                <Label htmlFor="proxy-source-query">{t("settings.proxySourceQuery")}</Label>
                <Textarea id="proxy-source-query" value={query} onChange={(e) => setQuery(e.target.value)} />
              </div>
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="grid gap-1.5">
                  <Label htmlFor="proxy-source-pages">{t("settings.proxySourcePages")}</Label>
                  <Input id="proxy-source-pages" type="number" min={1} max={10} value={pages} onChange={(e) => setPages(e.target.value)} />
                </div>
                {kind === "fofa" ? (
                  <div className="grid gap-1.5">
                    <Label htmlFor="proxy-source-email">{t("settings.proxySourceEmail")}</Label>
                    <Input id="proxy-source-email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder={t("settings.proxySourceCredsHint")} />
                  </div>
                ) : null}
                <div className="grid gap-1.5">
                  <Label htmlFor="proxy-source-key">
                    {kind === "hunter" ? t("settings.proxySourceHunterKey") : t("settings.proxySourceKey")}
                  </Label>
                  <Input id="proxy-source-key" type="password" value={key} onChange={(e) => setKey(e.target.value)} placeholder={t("settings.proxySourceCredsHint")} autoComplete="off" />
                </div>
              </div>
            </>
          )}
          <div className="flex items-center justify-between gap-4">
            <Label htmlFor="proxy-source-enabled" className="text-sm font-normal text-muted-foreground">
              {t("settings.proxySourceEnabled")}
            </Label>
            <Switch id="proxy-source-enabled" checked={enabled} onCheckedChange={setEnabled} />
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={() => void save()} disabled={busy}>
              {busy ? <Loader2Icon className="size-3.5 animate-spin" /> : null}
              {editingID === null ? t("settings.proxySourceAdd") : t("settings.save")}
            </Button>
            {editingID !== null ? (
              <Button size="sm" variant="outline" onClick={reset} disabled={busy}>
                {t("settings.cancel")}
              </Button>
            ) : null}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
