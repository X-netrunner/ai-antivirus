# The two-week soak (spec 14, M8)

This is the one milestone nobody can do for you: run AI Antivirus on **your own machine, doing your own work**, in
alert-only mode, and find out how often it is wrong. Nothing below acts on your system. In alert-only mode AI Antivirus
records and notifies; it never freezes, kills, quarantines, blocks or restores.

Pass criteria (from the spec): at least 14 days, every alert reviewed, **no alerts on your replayed benign activity that
you would call false**, and a written false-positive rate. Only then try `contain` with `dry_run = true`.

## 0. Before you start

```sh
cd packaging/arch && makepkg -f && sudo pacman -U ai-antivirus-*.pkg.tar.zst
ai-antivirus --config /etc/ai-antivirus/ai-antivirus.toml config-check --print | grep -n "mode"   # must say alert-only
sudo systemctl enable --now ai-antivirus-sensord ai-antivirus-engined
sudo -u ai-antivirus ai-antivirus trust-baseline          # what pacman installed becomes trusted
systemctl status ai-antivirus-sensord ai-antivirus-engined   # both active, no restart loop
sudo -u ai-antivirus ai-antivirus db-stats
```

Do **not** enable `ai-antivirus-responderd` during the soak. Leave `[ai] enabled = false` for the first week, so the
deterministic rules are measured on their own; turn the analyzer on in week two if you want to test it.

## 1. Keep your own record (the replay corpus)

The event log rotates (default 64 MiB x 6 files, which a busy desktop can fill in a day). Save a copy each evening so
the whole fortnight survives:

```sh
sudo install -d -m 0700 /root/ai-antivirus-soak
sudo cp /var/log/ai-antivirus/events.jsonl "/root/ai-antivirus-soak/events-$(date +%F).jsonl"
sudo -u ai-antivirus ai-antivirus alerts -n 100000 --json | sudo tee "/root/ai-antivirus-soak/alerts-$(date +%F).jsonl" >/dev/null
```

Raise `event_log_keep` in `/etc/ai-antivirus/ai-antivirus.toml` if you would rather keep more on disk.

## 2. Use the machine normally, and on purpose touch the known trouble spots

Do your real work. Make sure the fortnight also includes each of these at least once, because the README lists them as
likely sources of false positives:

- `pacman -Syu` (several times, including a kernel upgrade), `makepkg`, and AUR builds through your helper
- Steam / Proton games, Wine
- Docker or Podman containers (AV-B-0003 is known to fire on runc re-exec)
- AppImages and installers that run from `/tmp` (AV-B-0013)
- Your editor or IDE, language toolchains, `npm`/`cargo`/`pip` installs
- Browser use (including downloads), backups, `rsync`, archive and compression jobs
- Suspend/resume, logging out and in, a reboot

## 3. Each day (5 minutes)

```sh
sudo -u ai-antivirus ai-antivirus alerts -n 200 | less
sudo -u ai-antivirus ai-antivirus alerts -n 100000 --json | python3 scripts/soak-report.py
sudo -u ai-antivirus ai-antivirus integrity               # exits 1 if a package file differs from pacman's record
journalctl -u ai-antivirus-sensord -u ai-antivirus-engined --since yesterday -p warning
```

Write down for every alert: what were you doing, and was it real? If you do not recognise the program, treat it as real
until you have looked into it (`pacman -Qo PATH`, `file PATH`, `sha256sum PATH`).

## 4. Label and measure

```sh
sudo -u ai-antivirus ai-antivirus alerts -n 100000 --json | python3 scripts/soak-report.py --csv review.csv
# open review.csv and fill the `verdict` column: tp (real), fp (harmless, should not have alerted), ok (you did it on purpose)
python3 scripts/soak-report.py --rate review.csv
```

## 5. Tune only what you can explain

For a repeat offender that is clearly harmless, add an exclusion rather than weakening a rule. Put your own rules in
`/etc/ai-antivirus/rules/behavior/local/` with ids that start with `LOCAL-`; the shipped rules are owned by the package and
an upgrade replaces them. `exclude_exe` and `exclude_ancestor_exe` are the two knobs the shipped rules already use
(see `rules/behavior/00-shipped.toml`). Check the result against everything you recorded:

```sh
sudo cp /var/lib/ai-antivirus/ai-antivirus.db /root/ai-antivirus-soak/trust-copy.db      # a copy: --replay reads AND writes its database
sudo -u ai-antivirus ai-antivirus-engined --replay /root/ai-antivirus-soak/events-2026-MM-DD.jsonl \
    --rules /etc/ai-antivirus/rules --db /root/ai-antivirus-soak/trust-copy.db
```

(`--replay` runs a recorded event log through the engine, prints the alerts as JSON lines and acts on nothing; it needs
no running daemon. Without `--db` it starts with an empty trust cache, so pacman-owned files are not trusted and the
result differs from the live engine. Run it for each saved day. If the copy is not readable by `ai-antivirus`, `chown` the
copy first.)

Never silence a rule you cannot explain. A false positive you understand is a bug in a rule; one you do not understand
may be the real thing.

## 6. Exit criteria and next step

You are done when, for the last 7 days, every remaining alert is understood, replaying each saved day with your final
rules gives 0 alerts you would call false, and you have written down the false-positive rate (`--rate`). Keep a copy of
that report.

Only then, and only if you want automatic action: set `mode = 'contain'` **and** `dry_run = true`, start
`ai-antivirus-responderd`, and read `ai-antivirus actions` for another week. Every action it would have taken is recorded
there. Remember that freeze can be undone and kill cannot, and that levels 4 to 6 always wait for `ai-antivirus approve`.
