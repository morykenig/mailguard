/**
 * MailGuard - Gmail add-on entry points.
 *
 * Flow: message opened -> extract (Extract.gs, History.gs) -> signed POST to the
 * backend (Api.gs) -> render the explanation (Cards.gs). Results are cached per user
 * for a few minutes so re-opening an email is instant and doesn't spend intel quota.
 */

function onHomepage(e) {
  setLocale_(e);
  return buildHomepageCard_();
}

function onGmailMessageOpen(e) {
  setLocale_(e);
  return analyzeAndRender_(e, false);
}

/** "Re-scan" button: bypass the cache and replace the current card. */
function onRescan(e) {
  setLocale_(e);
  var card = analyzeAndRender_(e, true);
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(card))
    .build();
}

/** "How the score works" button. */
function onShowMethodology(e) {
  setLocale_(e);
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(buildMethodologyCard_()))
    .build();
}

function analyzeAndRender_(e, forceRescan) {
  var messageId = (e && e.gmail && e.gmail.messageId) || (e && e.parameters && e.parameters.messageId);
  if (!messageId) {
    return buildHomepageCard_();
  }
  try {
    if (!forceRescan) {
      var hit = cachedResult_(messageId);
      if (hit) {
        return buildResultCard_(hit, { cached: true, messageId: messageId });
      }
    }
    var result = analyzeMessage_(e, messageId);
    return buildResultCard_(result, { cached: false, messageId: messageId });
  } catch (err) {
    // Log the error *type* only - never message content.
    console.error('analysis failed: ' + (err && err.name) + ' ' + (err && err.kind ? err.kind : ''));
    return buildErrorCard_(err);
  }
}

/** Extract, sign, send, validate - and record the end-to-end time the user waited. */
function analyzeMessage_(e, messageId) {
  var started = Date.now();
  var config = getConfig_();
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var message = GmailApp.getMessageById(messageId);
  var payload = buildPayload_(message, messageId, config);
  var result = callBackend_(payload, config);
  result.client_ms = Date.now() - started; // includes extraction and network, not just the engine
  cacheResult_(messageId, result);
  // Remember the verdict for next time (salted hashes only; see History.gs) - but only when the
  // From address is authenticated. Otherwise anyone could forge mail "from" your colleague, get it
  // rated malicious, and poison the colleague's record for their genuine mail.
  var fromEmail = emailFromHeader_(message.getFrom());
  if (config.senderHistory && result.sender && result.sender.authenticated && result.sender.email === fromEmail) {
    recordVerdict_(fromEmail, messageId, result.verdict);
  }
  return result;
}

/** The language is part of the key: the backend writes explanations in the user's language. */
function cacheKey_(messageId) {
  return 'mg:' + MG.VERSION + ':' + MG_LOCALE_ + ':' + messageId;
}

function cachedResult_(messageId) {
  try {
    var hit = CacheService.getUserCache().get(cacheKey_(messageId)); // per-user, never shared
    return hit ? validateResult_(JSON.parse(hit)) : null; // re-validated: the cache is not a trust boundary
  } catch (err) {
    return null;
  }
}

/** Best effort: a cache failure must never turn a good result into an error card. */
function cacheResult_(messageId, result) {
  try {
    var serialized = JSON.stringify(result);
    if (Utilities.newBlob(serialized).getBytes().length < 95000) { // CacheService limit: 100 KB
      CacheService.getUserCache().put(cacheKey_(messageId), serialized, MG.CACHE_TTL_SECONDS);
    }
  } catch (err) {
    console.warn('result not cached: ' + err.name);
  }
}
