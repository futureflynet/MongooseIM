Logs
---

It is a good idea to store logs in one centralized place when working in a clustered environment.
MongooseIM uses Lager - the logging framework. Its backend can be easily replaced.
Some of the recommended backends are:

- https://github.com/basho/lager_syslog to use syslog and
- https://github.com/mhald/lager_logstash_backend for logstash (http://logstash.net/).

To change the backend you have to edit `rel/files/app.config`. Before that you need
to add the backend to deps in `rebar.config` file:

    {lager_syslog, ".*", {git, "git://github.com/basho/lager_syslog.git"}},

and execute:

    ./rebar get-deps

The following entry to rel/reltool.config has to be added

    {app, lager_syslog, [{incl_cond, include}]},


Monitoring
---

### graphite-collectd


To monitor MongooseIM during load testing we recommend the following open source applications:

- Graphite (http://graphite.wikidot.com/) is used for data presentation 
- collectd (http://collectd.org/) is a daemon running on monitored nodes capturing data related to CPU and Memory usage, IO etc. 

### mod_api_metrics

It provides REST interface for Mongoose's metrics, so it can be easily integrated
with other services.

You can read more about it here: [REST interface to metrics](/developers-guide/REST-interface-to-metrics)

### Wombat OAM

WombatOAM is an operations and maintenance framework for Erlang based systems. Its Web Dashboard displays this data in an aggregated manner and provides interfaces to feed the data to other OAM tools such as Graphite, Nagios or Zabbix.

For more information see:
https://www.erlang-solutions.com/products/wombat

### Built-in Exometer reporters

MongooseIM uses the Exometer libary for collecting the metrics. Exometer has many
build-in reporters that can send metrics to external services like:

* graphite
* amqp
* statsd
* snmp
* opentsdb

It is possible to enable them in Moongoose via  the `app.config` file. The file sits next
to the `ejabberd.cfg` file and both files are located in the `rel/files` and `_REL_DIR_/etc` directories.
For more details, please visit the Exometer's project page: [ExometerProject](https://github.com/Feuerlabs/exometer).

**Note that we are using the 1.1 version.**

Below you can find sample configuration, it setups graphite reporter which connects
to graphite running on localhost.

You can see an additional option not listed in the Exometer docs - `mongooseim_report_interval`.
That option sets metrics resolution - in other words: how often Exometer gathers and sends metrics
through reporters. By default that is 60 seconds.

```erl
...
{exometer, [
    {mongooseim_report_interval, 60000}, %% 60 seconds
    {report, [
        {reporters, [
                     {exometer_report_graphite, [
                                                 {prefix, "mongooseim"},
                                                 {connect_timeout, 5000},
                                                 {host, "127.0.0.1"},
                                                 {port, 2003},
                                                 {api_key, ""}
                                                ]}
                    ]}
    ]}
  ]}
...
```
