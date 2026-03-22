(function () {
  'use strict';

  function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? (meta.getAttribute('content') || '') : '';
  }

  function buildQuery(params) {
    var qp = new URLSearchParams();
    Object.keys(params || {}).forEach(function (key) {
      var value = params[key];
      if (value !== undefined && value !== null && String(value).length > 0) {
        qp.set(key, String(value));
      }
    });
    return qp.toString();
  }

  async function request(method, url, opts) {
    var options = opts || {};
    var query = buildQuery(options.params || {});
    var fullUrl = query ? (url + '?' + query) : url;

    var response = await fetch(fullUrl, {
      method: method,
      headers: Object.assign({
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken(),
      }, options.headers || {}),
      body: options.body ? JSON.stringify(options.body) : undefined,
      credentials: 'same-origin',
    });

    var payload = {};
    try {
      payload = await response.json();
    } catch (_err) {
      payload = {};
    }

    if (!response.ok || payload.success === false) {
      var msg = (payload.error && payload.error.message) || payload.message || ('API request failed (' + response.status + ')');
      throw new Error(msg);
    }

    return payload;
  }

  window.QuantumShieldApiClient = {
    request: request,
    get: function (url, params, headers) {
      return request('GET', url, { params: params || {}, headers: headers || {} });
    },
    post: function (url, body, headers) {
      return request('POST', url, { body: body || {}, headers: headers || {} });
    },
  };
})();
