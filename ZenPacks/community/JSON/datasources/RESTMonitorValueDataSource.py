import json
import logging

from ZenPacks.community.JSON.lib.utils import SkipCertifContextFactory
from ZenPacks.community.JSON.lib.jsonpath_ng.ext import parse

from twisted.internet.defer import returnValue, inlineCallbacks
from twisted.internet import reactor
from twisted.web.client import Agent, readBody
from twisted.web.http_headers import Headers

from zope.schema.vocabulary import SimpleVocabulary
from zope.component import adapts
from zope.interface import implements

from Products.Zuul.form import schema
from Products.Zuul.infos import ProxyProperty
from Products.Zuul.infos.template import RRDDataSourceInfo
from Products.Zuul.interfaces import IRRDDataSourceInfo
from Products.Zuul.utils import ZuulMessageFactory as _t

from ZenPacks.zenoss.PythonCollector.datasources.PythonDataSource import PythonDataSource, PythonDataSourcePlugin

log = logging.getLogger('zen.RESTMonitor')
SOURCETYPE = "RESTMonitorValue"


class RESTMonitorValueDataSource(PythonDataSource):
    """Explanation of what RESTMonitorValueDataSource does."""

    ZENPACKID = 'ZenPacks.community.JSON'

    # Friendly name for your data source type in the drop-down selection.
    sourcetypes = ('RESTMonitorValue',)
    sourcetype = sourcetypes[0]

    # Collection plugin for this type. Defined below in this file.
    plugin_classname = ".".join((__name__, "RESTMonitorValueDataSourcePlugin"))

    # Extra attributes for my type.
    hostname = '${dev/id}'
    port = 443
    useSsl = True
    skipCertCheck = False
    uri = '/'
    timeout = 60
    method = 'GET'
    headers = ''
    jsonPath = ''
    eventValues = ''
    valueType = 'String'
    invert = False

    _properties = PythonDataSource._properties + (
        {'id': 'hostname', 'type': 'string', 'mode': 'w'},
        {'id': 'port', 'type': 'int', 'mode': 'w'},
        {'id': 'useSsl', 'type': 'boolean', 'mode': 'w'},
        {'id': 'skipCertCheck', 'type': 'boolean', 'mode': 'w'},
        {'id': 'uri', 'type': 'string', 'mode': 'w'},
        {'id': 'timeout', 'type': 'int', 'mode': 'w'},
        {'id': 'method', 'type': 'string', 'mode': 'w'},
        {'id': 'headers', 'type': 'string', 'mode': 'w'},
        {'id': 'jsonPath', 'type': 'string', 'mode': 'w'},
        {'id': 'eventValues', 'type': 'lines', 'mode': 'w'},
        {'id': 'valueType', 'type': 'string', 'mode': 'w'},
        {'id': 'invert', 'type': 'boolean', 'mode': 'w'},
    )

    def addDataPoints(self):
        if not self.datapoints._getOb('status', None):
            self.manage_addRRDDataPoint('status')


class IRESTMonitorValueDataSourceInfo(IRRDDataSourceInfo):
    """Interface that creates the web form for this data source type."""

    hostname = schema.TextLine(
        group=_t('Connection'),
        title=_t('Hostname'))
    port = schema.Int(
        group=_t('Connection'),
        title=_t('Port'))
    useSsl = schema.Bool(
        group=_t('Connection'),
        title=_t('Use SSL ?'))
    skipCertCheck = schema.Bool(
        group=_t('Connection'),
        title=_t('Skip Certificate Check ?'))
    uri = schema.TextLine(
        group=_t('Connection'),
        title=_t('URI'))
    method = schema.Choice(
        group=_t('Connection'),
        vocabulary=SimpleVocabulary.fromValues([
            "GET",
            "POST",
        ]),
        title=_t('HTTP Method'))
    headers = schema.TextLine(
        group=_t('Parameters'),
        title=_t('Headers'))
    jsonPath = schema.TextLine(
        group=_t('JSON data'),
        title=_t('JSON Path'))
    eventValues = schema.Text(
        group=_t('JSON data'),
        title=_t('Values to create events'))
    valueType = schema.Choice(
        group=_t('JSON data'),
        vocabulary=SimpleVocabulary.fromValues([
            "String",
            "Numeric",
            "Integer",
            "Float",
            "Boolean",
        ]),
        title=_t('Values type'))
    invert = schema.Bool(
        group=_t('JSON data'),
        title=_t('Invert expression'))

class RESTMonitorValueDataSourceInfo(RRDDataSourceInfo):
    """Adapter between IRESTMonitorValueDataSourceInfo and RESTMonitorValueDataSource."""

    implements(IRESTMonitorValueDataSourceInfo)
    adapts(RESTMonitorValueDataSource)

    testable = False
    cycletime = ProxyProperty('cycletime')
    hostname = ProxyProperty('hostname')
    port = ProxyProperty('port')
    useSsl = ProxyProperty('useSsl')
    skipCertCheck = ProxyProperty('skipCertCheck')
    uri = ProxyProperty('uri')
    timeout = ProxyProperty('timeout')
    method = ProxyProperty('method')
    headers = ProxyProperty('headers')
    jsonPath = ProxyProperty('jsonPath')
    eventValues = ProxyProperty('eventValues')
    valueType = ProxyProperty('valueType')
    invert = ProxyProperty('invert')


class RESTMonitorValueDataSourcePlugin(PythonDataSourcePlugin):
    @classmethod
    def params(cls, datasource, context):
        params = dict()
        params["hostname"] = datasource.talesEval(datasource.hostname, context)
        params["port"] = datasource.port
        params["uri"] = datasource.uri
        params["useSsl"] = datasource.useSsl
        params["skipCertCheck"] = datasource.skipCertCheck
        params["timeout"] = datasource.timeout
        params["method"] = datasource.method
        params["headers"] = datasource.headers
        params["jsonPath"] = datasource.jsonPath
        params["eventValues"] = datasource.eventValues
        params["valueType"] = datasource.valueType
        params["invert"] = datasource.invert
        log.debug("REST params: {}".format(params))
        return params


    @inlineCallbacks
    def collect(self, config):
        log.debug('Starting RESTMonitorValue collect')
        ds0 = config.datasources[0]
        params = ds0.params

        scheme = 'https' if params['useSsl'] else 'http'
        url = '{}://{}:{}{}'.format(scheme, params['hostname'], params['port'], params['uri'])
        log.debug('url: {}'.format(url))

        if params['headers']:
            try:
                headers = json.loads(params['headers'])
            except Exception as e:
                log.error("Given headers have wrong syntax - {}".format(e.args))
            else:
                headers = {}
        else:
            headers = {
                "Content-type": ['application/json'],
                "User-Agent": ["Mozilla/3.0Gold"],
                }

        try:
            timeout = int(params['timeout'])
        except Exception as e:
            log.error("Timeout value is not valid: {} - {}".format(params['timeout'], e.args))
        else:
            timeout = 60

        if params['skipCertCheck']:
            agent = Agent(reactor, contextFactory=SkipCertifContextFactory(), connectTimeout=timeout)
        else:
            agent = Agent(reactor, connectTimeout=timeout)
        try:
            response = yield agent.request(params['method'], url, Headers(headers))
            response_body = yield readBody(response)
            response_body = json.loads(response_body)
            returnValue(response_body)
        except Exception as e:
            log.exception('{}: failed to get server data for {}'.format(config.id, ds0))
            log.exception('{}: failed with URL {}'.format(config.id, url))
            log.exception('{}: Exception: {}'.format(config.id, e.args))
            returnValue(e)
        returnValue(None)

    def onSuccess(self, result, config):
        log.debug('Success job RESTMonitorValueDataSourcePlugin - result is {}'.format(result))

        ds0 = config.datasources[0]
        jsonPath = ds0.params['jsonPath']
        eventValues = ds0.params['eventValues']
        valueType = ds0.params['valueType']
        invert = ds0.params['invert']

        data = self.new_data()
        if not (jsonPath and eventValues):
            log.warning("There is no data to analyze. Please fill in the JSON Path and the event Values")
            return data

        jsonpath_expression = parse(jsonPath)
        matches = jsonpath_expression.find(result)      # list
        if len(matches) == 0:
            log.warning("The JSONpath does not match any key.")
            return data
        elif len(matches) > 1:
            log.warning("The JSONpath is ambiguous and matches {} different keys.".format(len(matches)))

        match = matches[0]
        jsonValue = match.value
        originalValue = match.value
        log.debug("{} - Found value in JSON: {} ({})".format(ds0.datasource, jsonValue, type(jsonValue)))

        eventValues = eventValues.splitlines()
        if valueType == 'String':
            eventValues = [s.lower() for s in eventValues]
            jsonValue = jsonValue.lower()
        elif valueType == 'Integer':
            try:
                eventValues = [int(x) for x in eventValues]
                jsonValue = int(jsonValue)
            except:
                log.error('Could not cast values into an integer: {}'.format(eventValues))
        elif valueType == 'Float':
            try:
                eventValues = [float(x) for x in eventValues]
                jsonValue = float(jsonValue)
            except:
                log.error('Could not cast values into a float: {}'.format(eventValues))
        elif valueType == 'Boolean':
            try:
                eventValues = [x.capitalize() == "True" for x in eventValues]
                jsonValue = bool(jsonValue) # This shouldn't be required as the JSON object has been loaded in a dict
            except:
                log.error('Could not cast values into a boolean: {}'.format(eventValues))
        else:
            log.error('Wrong type of type value: {}'.format(valueType))
        log.debug("Event values: {}".format(eventValues))

        eventTrigger = jsonValue in eventValues
        if invert:
            eventTrigger = not eventTrigger

        if eventTrigger:
            severity = ds0.severity
        else:
            severity = 2

        msg = 'The JSON value in {} is {}.'.format(match.full_path, originalValue)
        data['events'].append({
            'device': config.id,
            'component': ds0.component,
            'severity': severity,
            'eventClass': ds0.eventClass,
            'eventKey': ds0.eventKey,
            'eventClassKey': '',
            'summary': msg,
            'message': msg,
        })
        return data

    def onError(self, result, config):
        log.debug('Error job RESTMonitorValueDataSourcePlugin - result is {}'.format(result))
        data = self.new_data()
        return data
