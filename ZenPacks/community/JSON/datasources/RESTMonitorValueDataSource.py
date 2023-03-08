import ast
import datetime
import json
import logging
import pytz


from ZenPacks.community.JSON.lib.utils import SkipCertifContextFactory

from twisted.enterprise import adbapi
from twisted.internet.defer import returnValue, inlineCallbacks, Deferred
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
    # plugin_classname = 'ZenPacks.community.JSON.datasources.RESTMonitorValueDataSource.RESTMonitorValueDataSourcePlugin'
    plugin_classname = ".".join((__name__, "RESTMonitorValueDataSourcePlugin"))

    # Extra attributes for my type.
    # pending_period = 0
    # timezone = 'Europe/Brussels'
    # kbo_query = 'EXECUTE [dbo].[up_HelpDeskEdpotPending];'
    # prsu_number_present = True
    # test_b = False

    hostname = '${dev/id}'
    ipAddress = '${dev/manageIp}'
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

    # TODO: Add case sensitive bool
    # TODO: Check certificate ?
    # TODO: "Accept": ['application/json']
    # TODO: Add payload ? JSON or in URL ?
    _properties = PythonDataSource._properties + (
        {'id': 'hostname', 'type': 'string', 'mode': 'w'},
        {'id': 'ipAddress', 'type': 'string', 'mode': 'w'},
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
    ipAddress = schema.TextLine(
        group=_t('Connection'),
        title=_t('IP Address'))
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
    ipAddress = ProxyProperty('ipAddress')
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
        log.info("RESTMonitorValueDataSourcePlugin params start")

        log.info("RESTparams1 : {}".format(datasource))
        log.info("RESTparams2 : {}".format(datasource.__dict__))
        log.info("RESTparams3 : {}".format(dir(datasource)))

        try:
            test = datasource.talesEval(datasource.hostname, context)
            log.info("RESTparamstest : {}".format(test))
        except Exception as e:
            log.info("RESTparamsE : {}".format(e.args))

        params = dict()
        params["hostname"] = datasource.talesEval(datasource.hostname, context)
        # params["hostname"] = datasource.hostname
        # params["ipAddress"] = datasource.talesEval(datasource.ipAddress, context)
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
        log.info("RESTparamsend")
        log.info("RESTparams: {}".format(params))
        return params

    '''
    @classmethod
    def config_key(cls, datasource, context):
        """
        Return list that is used to split configurations at the collector.
        """
        log.info('In config_key {} {} {} {}'.format(context.device().id,
                                                    datasource.getCycleTime(context),
                                                    datasource.rrdTemplate().id,
                                                    datasource.plugin_classname,
                                                    ))

        return (
            context.device().id,
            datasource.getCycleTime(context),
            datasource.rrdTemplate().id,
            datasource.plugin_classname,
        )
    '''

    @inlineCallbacks
    def collect(self, config):
        log.debug('Starting RESTMonitorValue collect')

        log.debug('datasources: {}'.format(config.datasources))

        ds0 = config.datasources[0]
        log.debug('ds0: {}'.format(ds0))
        log.debug('ds0: {}'.format(ds0.__dict__))
        params = ds0.params
        log.debug('params: {}'.format(params))

        scheme = 'https' if params['useSsl'] else 'http'
        url = '{}://{}:{}{}'.format(scheme, params['hostname'], params['port'], params['uri'])
        log.debug('url: {}'.format(url))

        # TODO: Test headers ?
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
            # response = yield agent.request('GET', url)
            response_body = yield readBody(response)
            log.debug('response_body: {}'.format(response_body))
            response_body = json.loads(response_body)
            returnValue(response_body)
        except Exception as e:
            log.exception('{}: failed to get server data for {}'.format(config.id, ds0))
            log.exception('{}: Exception: {}'.format(config.id, e.args))
            returnValue(e)
        returnValue(None)

    def onSuccess(self, result, config):
        log.debug('Success job RESTMonitorValueDataSourcePlugin - result is {}'.format(result))
        '''
        {'id': 'jsonPath', 'type': 'string', 'mode': 'w'},
        {'id': 'eventValues', 'type': 'lines', 'mode': 'w'},
        {'id': 'valueType', 'type': 'string', 'mode': 'w'},
        {'id': 'invert', 'type': 'boolean', 'mode': 'w'},
        '''

        ds0 = config.datasources[0]
        log.debug('ds0: {}'.format(ds0.__dict__))
        log.debug('ds0.params: {}'.format(ds0.params))
        jsonPath = ds0.params['jsonPath']
        eventValues = ds0.params['eventValues']
        valueType = ds0.params['valueType']
        invert = ds0.params['invert']

        data = self.new_data()
        if not (jsonPath and eventValues):
            log.warning("There is no data to analyze. Please fill in the JSON Path and the event Values")
            return data

        log.debug('jsonPath: {}'.format(jsonPath))
        log.debug('result: {}'.format(type(result)))

        # TODO: Cast values in valueType
        log.debug('valueType: {}'.format(valueType))

        # TODO: Keep original value without changing case
        jsonValue = self.parse_json_value(result, jsonPath)
        log.debug('jsonValue: {}'.format(jsonValue))

        eventValues = eventValues.splitlines()
        eventValues = [s.lower() for s in eventValues]
        log.debug('eventValues: {}'.format(eventValues))

        eventTrigger = jsonValue in eventValues
        log.debug('eventTrigger: {}'.format(eventTrigger))

        if invert:
            eventTrigger = not eventTrigger
        log.debug('eventTrigger: {}'.format(eventTrigger))

        if eventTrigger:
            severity = ds0.severity
        else:
            severity = 2

        msg = 'The JSON value is {}'.format(jsonValue)

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

    @staticmethod
    def parse_json_value(jsonObject, jsonPath):
        jsonPath = jsonPath.split('/')[1:]          # jsonPath must start with /
        log.debug('jsonPath list: {}'.format(jsonPath))

        if len(jsonPath) == 0:
            return None

        # TODO: What to do with lists ? How to catch the right element ?
        result = jsonObject
        for key in jsonPath:
            if not key in result:
                return None
            result = result[key]

        log.debug('result: {}'.format(result))
        return result.lower()
