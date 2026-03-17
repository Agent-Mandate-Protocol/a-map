SKILLS_DIR := skills

.PHONY: build test typecheck lint clean \
        skills-inspect skills-publish skills-search \
        skill-verify skill-sign skill-delegate

# ── Dev ──────────────────────────────────────────────────────────────────────

build:
	pnpm build

test:
	pnpm test

typecheck:
	pnpm typecheck

lint:
	pnpm lint

clean:
	pnpm clean

# ── ClawHub skills ───────────────────────────────────────────────────────────

## Inspect all three skills (shows what the server will parse — run before publish)
skills-inspect:
	clawhub inspect $(SKILLS_DIR)/amap-verify
	clawhub inspect $(SKILLS_DIR)/amap-sign
	clawhub inspect $(SKILLS_DIR)/amap-delegate

## Publish all three skills to ClawHub
skills-publish:
	clawhub publish $(SKILLS_DIR)/amap-verify
	clawhub publish $(SKILLS_DIR)/amap-sign
	clawhub publish $(SKILLS_DIR)/amap-delegate

## Search ClawHub to confirm skills are indexed after publishing
skills-search:
	clawhub search 'verify agent identity'
	clawhub search 'sign agent request'
	clawhub search 'delegate permissions to sub-agent'

## Publish individual skills
skill-verify:
	clawhub inspect $(SKILLS_DIR)/amap-verify
	clawhub publish $(SKILLS_DIR)/amap-verify

skill-sign:
	clawhub inspect $(SKILLS_DIR)/amap-sign
	clawhub publish $(SKILLS_DIR)/amap-sign

skill-delegate:
	clawhub inspect $(SKILLS_DIR)/amap-delegate
	clawhub publish $(SKILLS_DIR)/amap-delegate
