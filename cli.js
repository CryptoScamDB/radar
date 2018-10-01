#!/usr/bin/env node

const request = require('request');
const tldextract = require('tldextract');
const progress = require('cli-progress');
const colors = require('colors');
const Bottleneck = require('Bottleneck');
const config = require('./config');
const stringSimilarity = require('string-similarity');

const flatten = list => list.reduce((a, b) => a.concat(Array.isArray(b) ? flatten(b) : b), []);

const shuffle = (a) => {
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
}

const limiter = new Bottleneck({
	minTime: config.minTime,
	maxConcurrent: config.maxConcurrent
});

const extractHostname = (url) => {
	return new Promise((resolve,reject) => {
		tldextract(url, function (err, obj) {
			if(err) {
				reject(err);
			} else {
				resolve(obj.domain);
			}
		});
	});
}

const getBlacklist = () => {
	console.log("Getting blacklist...");
	return new Promise((resolve,reject) => {
		request('https://cryptoscamdb.org/api/blacklist',{json:true},(err,response,body) => {
			if(err) {
				reject(err);
			} else {
				resolve(body.filter(entry => !entry.startsWith('www.')));
			}
		});
	});
}

const getWhitelist = () => {
	console.log("Getting whitelist...");
	return new Promise((resolve,reject) => {
		request('https://cryptoscamdb.org/api/whitelist',{json:true},(err,response,body) => {
			if(err) {
				reject(err);
			} else {
				resolve(body);
			}
		});
	});
}

const getTLDs = () => {
	console.log("Getting list of TLDs...");
	return new Promise((resolve,reject) => {
		request('http://data.iana.org/TLD/tlds-alpha-by-domain.txt',(err,response,body) => {
			if(err) {
				reject(err);
			} else if(!body) {
				console.error('No body for TLDS?');
				process.exit();
			} else {
				resolve(body.split('\n').filter(tld => !tld.startsWith('#')).map(tld => tld.toLowerCase()));
			}
		});
	});
}

const rawFetch = (async url => {
	return new Promise(resolve => {
		request('http://' + url,{},(err,response,body) => {
			if(err || !body) {
				resolve(false);
			} else {
				resolve(body);
			}
		});
	});
})

const fetch = limiter.wrap(rawFetch);


(async () => {
	const bar = new progress.Bar({
		format: 'Requests completed |' + colors.cyan('{bar}') + '| {percentage}% || {value}/{total} ',
        barCompleteChar: '\u2588',
        barIncompleteChar: '\u2591',
		hideCursor: true
	});
	const tlds = await getTLDs();
	const blacklist = await getBlacklist();
	const whitelist = await getWhitelist();
	
	console.log("Parsing whitelist...");
	
	const whitelistContent = await Promise.all(whitelist.map(async entry => {
		const content = await rawFetch(entry);
		const hostname = await extractHostname(entry);
		return ({
			url: hostname,
			content: content
		});
	}));
	
	console.log("Extracting whitelist entries...");
	
	const domains = await Promise.all(whitelist.map(async entry => {
		const hostname = await extractHostname(entry);
		return tlds.map(tld => ({ url: hostname + '.' + tld, parent: hostname }));
	}));
	
	console.log("Success!");
	
	bar.start(flatten(domains).length, 0);
	
	await Promise.all(shuffle(flatten(domains)).map(async domain => {
		const valid = await fetch(domain.url);
		if(valid && !(blacklist.includes(domain.url)) && !(whitelist.includes(domain.url))) {
			const similarity = stringSimilarity.compareTwoStrings(whitelistContent.find(entry => entry.url == domain.parent).content, valid);
			if(similarity > config.similarityThreshold) {
				console.error('\nPossible phishing URL found! ' + domain.url + ' (' + Math.round(similarity*1000)/10 + '%)');
			}
		}
		bar.increment();
	}));
})();