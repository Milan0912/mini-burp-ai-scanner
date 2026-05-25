'use strict';

/**
 * Parameter Classifier v2
 * ========================
 * Maps parameter names to attack strategy classes.
 * Covers real-world naming conventions from JSP, PHP, ASP.NET, Django, Rails.
 */

function classifyParameter(paramName) {
    const name = (paramName || '').toLowerCase().trim();

    // ── Auth / Credentials ───────────────────────────────────────────
    const authExact = /^(auth|token|jwt|session|login|logout|password|passwd|pwd|pass|secret|username|user|uname|email|mail|credential|apikey|api_key|access_token|userid)$/;
    const authFuzzy = /pass(word)?|user(name)?|login|email|credential/i;
    if (authExact.test(name) || authFuzzy.test(name)) return 'auth';

    // ── Numeric ID / Object reference ────────────────────────────────
    const idExact = /^(id|uid|user_id|account_id|profile_id|product_id|item_id|order_id|record_id|cat|category|article|news|post|page_id|thread|forum|topic|msg|pid|tid|cid|eid|fid|gid|nid|aid|bid|did|mid|oid|rid|sid|wid|no|num)$/;
    if (idExact.test(name) || /_id$/.test(name) || /^id_/.test(name)) return 'id';

    // ── File / Path (LFI) ────────────────────────────────────────────
    const fileExact = /^(file|path|dir|folder|include|require|template|doc|document|page|content|load|import|src|source|resource|asset|view|layout|module|config|conf)$/;
    const fileFuzzy = /file|path|template|include|content|page|view/i;
    if (fileExact.test(name) || fileFuzzy.test(name)) return 'file';

    // ── Search / Input (XSS + SQLi) ─────────────────────────────────
    const searchExact = /^(search|q|query|find|filter|keyword|term|text|input|name|title|subject|message|comment|description|note|body|data|value|val|s|k|kw|qs|sq)$/;
    const searchFuzzy = /search|query|keyword|comment|message|description/i;
    if (searchExact.test(name) || searchFuzzy.test(name)) return 'search';

    // ── Open Redirect ────────────────────────────────────────────────
    const redirectExact = /^(url|redirect|return|next|goto|link|ref|referrer|back|destination|target|continue|forward)$/;
    if (redirectExact.test(name)) return 'redirect';

    // ── Numeric-looking → probably an ID ────────────────────────────
    if (/^(num|number|count|amount|qty|quantity|price|total)$/.test(name)) return 'id';

    return 'misc';
}

module.exports = { classifyParameter };
