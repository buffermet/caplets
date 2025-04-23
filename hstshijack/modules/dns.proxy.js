var addr = env("iface.ipv4");

var Rrtype = {
	None:  0,
	A:     1,
//	CNAME: 5,
//	AAAA:  28,
};

var rxTargetedTlds = /\.(?:corn|clarity\.ns|googl|nel|ni|rne|al|cc\.uk|ch)[.]?$/ig;

String.prototype.isTargeted = function() {
	rxTargetedTlds.lastIndex = 0;
	return rxTargetedTlds.test(this);
};

// We immediately reply to prevent DNS tunneling
function onRequest(req, res) {
	res.Header.Response = true;
	res.Header.RecursionAvailable = true;

	req.Questions.forEach(function(question) {
		if (question.Qtype === Rrtype.A) {
			if (question.Name.isTargeted()) {
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

	if (res.Answers.length === 0) {
		res.Header.Rrtype = Rrtype.None;

		// Silence DNS errors by clearing all records
		res.Extras = [];
		res.Nameserver = [];
	}
}

function onResponse(req, res) {
	console.log(JSON.stringify(res, "\t", 1));
}

