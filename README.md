<!--- Top of README Badges (automated) --->
[![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/WIPACrepo/http-data-transfer-client?include_prereleases)](https://github.com/WIPACrepo/http-data-transfer-client/) [![Lines of code](https://img.shields.io/tokei/lines/github/WIPACrepo/http-data-transfer-client)](https://github.com/WIPACrepo/http-data-transfer-client/) [![GitHub issues](https://img.shields.io/github/issues/WIPACrepo/http-data-transfer-client)](https://github.com/WIPACrepo/http-data-transfer-client/issues?q=is%3Aissue+sort%3Aupdated-desc+is%3Aopen) [![GitHub pull requests](https://img.shields.io/github/issues-pr/WIPACrepo/http-data-transfer-client)](https://github.com/WIPACrepo/http-data-transfer-client/pulls?q=is%3Apr+sort%3Aupdated-desc+is%3Aopen) 
<!--- End of README Badges (automated) --->
# http-data-transfer-client
HTTP(s) data transfer client with OAuth2

## Using directly

First, set up the environment with `setupenv.sh`.  Then load it with `. env/bin/activate`.

Now, copy files:

```
python -m http_data_transfer_client <src_file(s)> <dest>
```

## Using the container

Example:

```
docker run --rm -it -v /my/data/dir --network=host https://data.icecube.aq/data/user/my/file /my/data/dir/file
```
