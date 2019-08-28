#!/usr/bin/python3

# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Module for interacting with Deputy API.

This module connects to the third-party REST API[1], and translates responses
into python objects with a slightly differing naming convention. Requests to the
REST API handled in the Deputy object.

The Deputy API queried is a hosted instance for each customer of the product[1].
The convention employed is 'https://<hostname>.<region>.deputy.com', with
hostname and region being chosen in the agreement with the Deputy team proper.

The objects created using this module have their names changed slightly from how 
Deputy defines them. This is done to understand the intent of the response a bit
more directly. Hierarchy of a Queue defined by Deputy:

OperationalUnit
| \
| Training modules required to schedule
|
Roster
|
Employee
  \
  Training records applied

We redefine this slightly to be:

Queue
| \
| Trainings required to schedule
|
Shift
|
Employee
  \
  Trainings

Usage:

  import deputy

  # There are two ways to instantiate the Deputy object. To use the flag values
  # provided when launching the binary:
  client = deputy.Deputy.from_flags()

  # Or, to provide explicit values desired:
  client = deputy.Deputy(endpoint='https://example.com')

  # Then, python objects representing a Deputy resource can be obtained using
  # one of the deputy.Deputy object's getters.
  employee_query = deputy.Query(
    select={'active': {'field': 'Active', 'type': 'eq', 'data': True},
            'id': {'field': 'Id', 'type': 'eq', 'data': $ID}},
    join=['ContactObject', 'StressProfileObject', 'CompanyObject'])
  employees = client.get_employees(employee_query=employee_query)
  # And now, you have a list of strictly typed objects to interact with!

The most common use case for this module is to find 'employees on shift right
now'. To find employees on shift during another time, you can change the value
provided for the `--current_datetime_override` flag. To find 'employees on shift
right now':

  import deputy

  client = deputy.Deputy.from_flags()

  shift_query = deputy.Query(
    select={'Employee_0': {'field': 'Employee', 'type': 'ne', 'data': 0},
            'StartTime': {'field': 'StartTime', 'type': 'le',
                          'data': client.get_current_time().timestamp()},
            'EndTime': {'field': 'EndTime', 'type': 'ge',
                        'data': client.get_current_time().timestamp()}},
    join=['EmployeeObject'])

  shifts = client.get_shifts(shift_query)
  employees = {shift.employee for shift in shifts}
  return list(employees)


Note that, at current, this module does not have a representation of all objects
in the Deputy API. Instead, it provides a framework to add new types of
responses as use cases arise, and abstracts away construction of the request to
the API.

[1] https://www.deputy.com/api-doc/API/Getting_Started
"""

import abc
import datetime
import json
import re
from typing import Any, Dict, List, Optional, Text, Union
import urllib

from absl import app
from absl import flags
from absl import logging

import attr
import dateutil.parser
import urllib3

FLAGS = flags.FLAGS

URI_VALIDATOR = re.compile(
    r'https://([\w\d]+|\{0?\})\.[\w\d]+\.deputy.com/api/v1/')

# Custom type definitions

ApiSelectType = Dict[Text, Dict[Text, Union[Text, int]]]

DeputyResourceNames = List[Text]

Employees = List['Employee']

Leaves = List['Leave']

Queues = List['Queue']

Shifts = List['Shift']

StressProfiles = List['StressProfile']

Trainings = List['Training']


flags.DEFINE_string(
    'endpoint_hostname',
    'example',
    'Hostname for Deputy instance.')

flags.DEFINE_string(
    'deputy_auth_token', '', 'Auth token created using '
    'https://www.deputy.com/api-doc/API/Authentication.')

flags.DEFINE_string(
    'uri_regional_endpoint',
    'https://{0}.au.deputy.com/api/v1/',
    'Parameterized uri path of a Deputy instance. String should accept a '
    'hostname, formattable using str.format().')

flags.DEFINE_string(
    'current_datetime_override',
    None,
    'Used to override the call to datetime.datetime.utcnow(). This allows for '
    'contacting the Deputy instance for shift data during any specific time. '
    'Must be of format "YYYY-MM-DD  HH:MM:SS". This value will be interpreted '
    'as a UTC time.')

flags.DEFINE_integer(
    'deputy_request_timeout',
    10,
    'Timeout for http request to Deputy API in seconds.')

flags.DEFINE_bool(
    'page_api_requests',
    False,
    'Boolean for paging requests to the API. Responses from the Deputy API are '
    'always hard-capped at 500 records. This will allow obtaining all results '
    'when more than 500 records for a request exist.')

flags.DEFINE_integer(
    'maximum_request_page_depth',
    2,
    'Maximum depth of pages to request from api. Each page is 500 records. Here'
    ' to prevent queries from accidentally making massive requests and bogging '
    'tasks to a halt.')

flags.register_validator(
    'uri_regional_endpoint',
    lambda value: value is None or URI_VALIDATOR.match(value),
    message='--uri_regional_endpoint must be of format '
    '"https://{}.<country_code>.deputy.com/api/v1/".')

flags.register_validator(
    'current_datetime_override',
    lambda value: value is None or _validate_timestamp_string(value),
    message='--current_datetime_override must be of format '
    '"YYYY-MM-DD HH:MM:SS".')


def _validate_timestamp_string(timestamp_value: Text) -> bool:
  """Validates that a timestamp string is parseable by datetime.

  Args:
    timestamp_value: string depicting timestamp
      (intended format is YYYY-MM-DD HH:MM:SS).

  Returns:
    bool to be interpreted by flag validator.
  """
  try:
    dateutil.parser.parse(timestamp_value)
    return True
  except ValueError:
    return False


def _validate_api_select(
    instance: 'Query',
    attribute: attr.Attribute,
    value: Optional[ApiSelectType],
    ) -> None:
  """Validates expected keys present in ApiSelectType attributes.

  Allows for an attr.s class attribute validator for ApiSelectType:
  http://www.attrs.org/en/stable/examples.html#validators

  Args:
    instance: Class of attribute being validated.
    attribute: Attribute being validated.
    value: Dictionary to check for expected keys.

  Raises:
    ValueError if keys are not expected.
  """
  del instance  # Unused.
  if value is None:
    return
  for subdictionary in value.values():
    if set(subdictionary.keys()) == {'field', 'type', 'data'}:
      continue
    if set(subdictionary.keys()) == {'field', 'type', 'data', 'join'}:
      continue
    raise ValueError('%s does not have expected keys.' % attribute)
  if 'f1' in value.keys():
    raise ValueError('"f1" key must not be present in attribute: %s.' %
                     attribute)


@attr.s(auto_attribs=True)
class Query(object):
  """Object representation of a query payload to Deputy API.

  Class attributes reflect specific components of the JSON the API expects.
  To send to the API:
    query = Query(*args)
    body = json.dumps(query.to_dict()).encode('utf-8')
    POST(body)

  In attributes with a 'type' key, this is the equivalent of a search operator.
  Available operators can be seen in upstream documentation under
  '/resource/:object/QUERY': https://www.deputy.com/api-doc/API/Resource_Calls

  Most attributes below correspond to the query fields documented upstream here:
  https://www.deputy.com/api-doc/API/Resource_Calls#page_POST_resourceobjectQUERY

  Attributes:
    key: Sets the search 'field' in the base query to a specific str value.
      Ex: {'f1': {'data': '', 'field': key, 'type': 'is'}}
    sort: Response key to sort the query by.
    join: Joining foreign objects to the query. Ex:
      ['EmployeeObject', 'ContactObject'].
    assoc: Associated objects of the resource. Ex:
      ['TrainingModule'] for OperationalUnit Deputy resource.
    select: 'search_identifier' to 'field', 'type', and
      'data' keys. Ex: {'Employee_0': {'field': 'Employee', 'data': 0,
                                       'type': 'ne'}}.
    join_select: 'search_identifier' to 'field', 'type',
      'data', and 'join' keys. Ex:
      {'Employee_0': {'field': 'Employee', 'data': 0, 'type: 'ne',
                      'join': 'ForeignObj'}}.
    raw: Arbitrary key:value pairs to extend the request.
    start: Record to start from in a request. Responses from the Deputy
      API are limited to 500 records, so to get the next 'page' increment this
      by 500.
  """
  key: Text = 'Id'
  sort: Text = 'Id'
  join: Optional[DeputyResourceNames] = None
  assoc: Optional[DeputyResourceNames] = None
  select: Optional[ApiSelectType] = attr.ib(
      validator=_validate_api_select, default=None)
  join_select: Optional[ApiSelectType] = attr.ib(
      validator=_validate_api_select, default=None)
  raw: Optional[Dict[Text, Any]] = None
  start: int = 0

  def to_dict(self) -> Dict[Text, Union[Text, int, Dict[Text, Any]]]:
    """Transforms query into a dictionary."""
    if not any((self.select, self.join_select, self.join, self.raw)):
      return {}

    query = {
        'search': {
            'f1': {
                'field': self.key,
                'type': 'is',
                'data': ''
            }
        },
        'sort': {
            self.sort: 'asc'
        },
        'join': self.join,
        'assoc': self.assoc,
        'start': self.start,
        # All results from the API are hard-capped at 500 upstream.
        'max': 500,
    }

    if self.select is not None:
      query['search'].update(self.select)

    if self.join_select is not None:
      query['search'].update(self.join_select)

    if self.raw is not None:
      query.update(self.raw)

    return query  # pytype: disable=bad-return-type


class DeputyAPIResponse(object):
  """Base class for object representations of API Responses."""

  __metaclass__ = abc.ABCMeta

  @classmethod
  @abc.abstractmethod
  def from_api_response(cls) -> 'DeputyAPIResponse':
    """Instantiate DeputyAPIResponse from API Response dictionaries.

    This function can take a variable amount of parameters, but should either
    be dictionaries (a response from the API), bools on including specific
    parameters, or other DeputyAPIResponse objects to join.
    """


@attr.s(auto_attribs=True)
class Training(DeputyAPIResponse):
  """Represents a training within Deputy.

  In Deputy, trainings are used to determine what queue/what type of work can be
  routed to a user.

  Attributes:
    name: Name of the training.
    comment: Comment describing the training.
  """
  name: Text
  comment: Text

  @classmethod
  def from_api_response(
      cls,
      api_response: Dict[Text, Any],
      ) -> 'Training':
    """Instantiates Training from API response.

    Instantiation requires a TrainingModule dictionary from the Deputy API.
    Typically this is joined on a request for 'resource/TrainingRecord/QUERY' or
    'resource/OperationalUnit/QUERY'. This corresponds to the Deputy
    API object:
    https://www.deputy.com/api-doc/Resources/TrainingModule

    Args:
      api_response: TrainingModule resource from Deputy API.

    Returns:
      Training object with expected attributes.
    """
    return cls(
        name=api_response.get('Title', ''),
        comment=api_response.get('Comment', ''))


@attr.s(auto_attribs=True)
class StressProfile(DeputyAPIResponse):
  """Represents a stress profile within Deputy.

  In Deputy, stress profiles are used to limit the time an Employee can work
  before becoming 'stressed':
  https://help.deputy.com/en/articles/1945481-stress-profile-and-fatigue-management

  Attributes:
    profile_id: Id of the stress profile.
    profile_name: Name of the stress profile.
    max_hours_per_shift: Maximum number of hours that can be worked in a single
      shift.
    max_hours_per_week: Maximum number of hours that can be worked in a
      single week.
    max_days_per_week: Maximum number of days user can work in a week.
    max_hours_per_day: Maximum number of hours that can be worked in a day.
    gap_hours_between_shifts: Minimum number of hours needed between shifts.
    creator_id: Id of user that created the profile.
    created: Time when the stress profile was created.
    modified: Time when the stress profile was last edited.
  """
  profile_id: int
  profile_name: Text
  max_hours_per_shift: int
  max_hours_per_week: int
  max_days_per_week: int
  max_hours_per_day: int
  gap_hours_between_shifts: int
  creator_id: int
  created: datetime.datetime
  modified: datetime.datetime

  @classmethod
  def from_api_response(
      cls,
      api_response: Dict[Text, Any],
      ) -> 'StressProfile':
    """Instantiates StressProfile from API Response.

    This method requires the dictionary response corresponding to this object:
    https://www.deputy.com/api-doc/Resources/StressProfile. This is usually
    obtained by joining to the Employee request.

    Args:
      api_response: dict, Response from 'resource/StressProfile/QUERY'.

    Returns:
      StressProfile with values from API Response.

    Raises:
      KeyError when required keys are not present.
    """
    created = dateutil.parser.parse(api_response['Created'])
    created.astimezone(dateutil.tz.UTC)
    modified = dateutil.parser.parse(api_response['Modified'])
    modified.astimezone(dateutil.tz.UTC)
    return cls(
        profile_id=api_response['Id'],
        profile_name=api_response.get('Name', ''),
        max_hours_per_shift=int(api_response.get('MaxHoursPerShift', 0)),
        max_hours_per_week=int(api_response.get('MaxHoursPerPeriod', 0)),
        max_days_per_week=int(api_response.get('MaxDaysPerPeriod', 0)),
        max_hours_per_day=int(api_response.get('MaxHoursPerDay', 0)),
        gap_hours_between_shifts=int(
            api_response.get('GapHoursBetweenShifts', 0)),
        creator_id=api_response.get('Creator', 0),
        created=created,
        modified=modified)


@attr.s(auto_attribs=True)
class Employee(DeputyAPIResponse):
  """Represents an employee within Deputy.

  Attributes:
    user_id: User unique identifier.
    display_name: Name of user. Ex: "Johnny Cache".
    first_name: First name of user. Ex: "Johnny".
    last_name: Last name of user. Ex: "Cache".
    email_address: Full email of user. Ex: "johnnycache@domain.com".
    start_date: Time that employee was added to Deputy.
    termination_date: Time that employee was exited in Deputy. None when
      employee is still active.
    active: Whether or not user is active in Deputy.
    creator_id: User id that created this user.
    username: Username. Ex: "johnnycache".
    location: Location user is in within Deputy.
    stress_profile: Stress profile applied to user.
    trainings: List[Training], Trainings an employee has. Optional, as
      gathering trainings requires additional calls to the upstream API (which
      can become expensive).
  """
  user_id: int
  display_name: Text
  first_name: Text
  last_name: Text
  email_address: Text
  start_date: Optional[datetime.datetime]
  termination_date: Optional[datetime.datetime]
  active: bool
  creator_id: int
  username: Text
  location: Text
  stress_profile: Optional[StressProfile] = None
  trainings: Optional[List[Training]] = None

  @classmethod
  def from_api_response(
      cls,
      api_response: Dict[Text, Any],
      training_api_response: List[Dict[Text, Any]] = None,
      ) -> 'Employee':
    """Instantiates Employee from API response.

    For all fields to be completely filled, this method requires the request to
    'resource/Employee/QUERY' (api_response) to be joined on ContactObject,
    CompanyObject, and StressProfileObject.

    Args:
      api_response: 'resource/Employee/QUERY' response.
      training_api_response: 'resource/TrainingRecord/QUERY' response.

    Returns:
      Employee instance with values from api response.

    Raises:
      KeyError when required keys are not present.
    """
    trainings = training_api_response
    if trainings is not None:
      trainings = [Training.from_api_response(training.get('ModuleObject', {}))
                   for training in trainings]
    stress_profile = api_response.get('StressProfileObject')
    if stress_profile is not None:
      stress_profile = StressProfile.from_api_response(stress_profile)

    start_date = api_response.get('StartDate')
    if start_date is not None:
      start_date = dateutil.parser.parse(start_date)
      start_date.astimezone(dateutil.tz.UTC)

    termination_date = api_response.get('TerminationDate')
    if termination_date is not None:
      termination_date = dateutil.parser.parse(termination_date)
      termination_date.astimezone(dateutil.tz.UTC)

    email = api_response.get('ContactObject', {}).get('Email', '')
    if isinstance(email, str):
      username = email.split('@')[0]
    else:
      username = email

    return cls(
        user_id=api_response['Id'],
        display_name=api_response.get('DisplayName', ''),
        first_name=api_response.get('FirstName', ''),
        last_name=api_response.get('LastName', ''),
        email_address=email,
        start_date=start_date,
        termination_date=termination_date,
        active=api_response.get('Active', True),
        creator_id=api_response.get('Creator', 0),
        username=username,
        location=api_response.get('CompanyObject', {}).get(
            'CompanyName', ''),
        stress_profile=stress_profile,
        trainings=trainings)


@attr.s(auto_attribs=True)
class Shift(DeputyAPIResponse):
  """Represents a shift within Deputy.

  In the API's terminology, a 'shift' is a roster, and a 'queue' is an
  operational unit. Multiple shifts exist inside a queue.

  Attributes:
    queue_id: Unique ID of the queue this shift is under.
    start_time: Time that shift starts.
    end_time: Time that shift ends.
    description: Description of the shift.
    employee: Employee scheduled for this shift.
  """
  queue_id: int
  start_time: datetime.datetime
  end_time: datetime.datetime
  description: Text
  employee: Employee

  @classmethod
  def from_api_response(
      cls,
      api_response: Dict[Text, Any],
      employee: Employee,
      ) -> 'Shift':
    """Instantiates Shift from API Response.

    This method requires the dictionary response corresponding to:
    https://www.deputy.com/api-doc/Resources/Roster.

    Args:
      api_response: Response from 'resource/Roster/QUERY'.
      employee: Employee scheduled for this shift. While it is
        possible to join the Roster resource request to the Employee object in
        Deputy, that does not give us all needed fields. Therefore, we expect
        a fully made Employee object to be passed in.

    Returns:
      Shift object with corresponding values.

    Raises:
      KeyError when required attributes aren't present in the dictionary.
    """
    start_time = datetime.datetime.fromtimestamp(api_response['StartTime'],
                                                 tz=dateutil.tz.UTC)
    end_time = datetime.datetime.fromtimestamp(api_response['EndTime'],
                                               tz=dateutil.tz.UTC)
    return cls(
        queue_id=api_response['OperationalUnit'],
        start_time=start_time,
        end_time=end_time,
        description=api_response.get('Comment', ''),
        employee=employee)


@attr.s(auto_attribs=True)
class Queue(DeputyAPIResponse):
  """Represents a queue within Deputy.

  In the API's terminology, a 'shift' is a roster, and a 'queue' is an
  operational unit. Multiple shifts exist inside a queue.

  Attributes:
    queue_id: Unique ID for this queue.
    queue_name: Name of the queue. Ex: 'Platform Primary Queue'.
    location: Location code for queue's region. Ex: 'West Coast'.
    trainings: Trainings needed for an employee to be scheduled on
      this queue.
    shifts: Shifts that are grouped as part of this queue.
  """
  queue_id: int
  queue_name: Text
  location: Text
  trainings: Optional[Trainings]
  shifts: Optional[Shifts]

  @classmethod
  def from_api_response(
      cls,
      api_response: Dict[Text, Any],
      shifts: Optional[Shifts] = None,
      ) -> 'Queue':
    """Instantiates Queue from API Response.

    This method requires the dictionary response corresponding to:
    https://www.deputy.com/api-doc/Resources/OperationalUnit. Full instantiation
    relies on the API requested being joined on 'TrainingModule' and
    'CompanyObject'.

    Args:
      api_response: Response from 'resource/OperationalUnit/QUERY',
        joined on TrainingModule.
      shifts: Shift objects within this queue.

    Returns:
      Queue object with corresponding values.

    Raises:
      KeyError when required keys aren't present in API response.
    """
    trainings = [Training.from_api_response(training_dict)
                 for training_dict in api_response.get('TrainingModule', [])]
    return cls(
        queue_id=api_response['Id'],
        queue_name=api_response.get('OperationalUnitName', ''),
        location=api_response.get('CompanyObject', {}).get('CompanyName', ''),
        trainings=trainings,
        shifts=shifts)


@attr.s(auto_attribs=True)
class Leave(DeputyAPIResponse):
  """Represents a leave within Deputy.

  Attributes:
    comment: Description of the leave.
    start_time: Time that this leave starts at.
    end_time: Time that this leave ends at.
    employee: Employee this leave event corresponds to.
  """
  comment: Text
  start_time: datetime.datetime
  end_time: datetime.datetime
  employee: Employee

  @classmethod
  def from_api_response(
      cls,
      api_response: Dict[Text, Any],
      employee: Employee,
      ) -> 'Leave':
    """Instantiates Leave from API Response.

    This method requires the dictionary response corresponding to this object:
    https://www.deputy.com/api-doc/Resources/Leave.

    Args:
      api_response: Response from 'resource/Leave/QUERY'.
      employee: Employee this leave corresponds to. Typically found
        via Deputy.get_employees, and mapping based on employee id.

    Returns:
      Leave object with corresponding values.

    Raises:
      KeyError when required keys aren't present in API response.
    """
    start_time = datetime.datetime.fromtimestamp(api_response['Start'],
                                                 tz=dateutil.tz.UTC)
    end_time = datetime.datetime.fromtimestamp(api_response['End'],
                                               tz=dateutil.tz.UTC)
    return cls(
        comment=api_response['Comment'],
        start_time=start_time,
        end_time=end_time,
        employee=employee)


class Deputy(object):
  """Object to query Deputy's REST API.

  Attributes:
    datetime_override: Testing seam to override
      datetime.now(). Defaults to None, and if set is a string
      parseable by dateutil.parser.parse().
    endpoint: Deputy API endpoint_hostname. For example:
        '1234567' or 'google-cloud'. This is selected by Deputy team.
    http: Http object for contacting the API.
    timeout: Http timeout in milliseconds.
    page_api_requests: Whether or not to page through requests. API
      responses are limited to 500 records, so this allows requesting more
      than 500 records from the API.
    maximum_page_depth: Maximum number of pages to request. Here to limit
      requests that are unexpectedly large.
  """

  @classmethod
  def from_flags(cls) -> 'Deputy':
    """Instantiate Deputy class using values in FLAGS."""
    endpoint = FLAGS.uri_regional_endpoint.format(FLAGS.endpoint_hostname)
    return cls(endpoint,
               urllib3.PoolManager(),
               FLAGS.deputy_auth_token,
               FLAGS.current_datetime_override,
               FLAGS.deputy_request_timeout,
               page_api_requests=FLAGS.page_api_requests,
               maximum_page_depth=FLAGS.maximum_request_page_depth)

  def __init__(self,
               endpoint: Text,
               http: urllib3.PoolManager,
               token: Text,
               datetime_override: Optional[Text] = None,
               timeout: int = 10,
               page_api_requests: bool = False,
               maximum_page_depth: int = 1) -> None:
    """Initializer.

    Directly initializes the Deputy object without using module flags. To use
    values from module flags, create this instance via 'from_flags()'.

    Args:
      endpoint: Fully formatted Deputy API URI. Ex:
        'https://example.na.deputy.com/api/v1/'.
      http: Http object used to contact the API.
      token: Oauth token used to authenticate API call.
      datetime_override: Parseable by dateutil.parser.parse()
        to override time used when querying Deputy API.
      timeout: Http timeout in milliseconds.
      page_api_requests: Whether or not requests to the API should ask
        for the next page upon hitting 500 records in the response.
      maximum_page_depth: Maximum number of pages to request.

    Raises:
      ValueError: endpoint is not of an expected format.
    """
    self.endpoint = endpoint
    if not URI_VALIDATOR.match(self.endpoint):
      raise ValueError(
          'endpoint must be of format: %s, got %s' % (
              'https://<hostname>.<country_code>.deputy.com/api/v1/',
              self.endpoint))
    self.http = http
    self.datetime_override = datetime_override
    self._headers = {
        'Authorization': 'OAuth {0}'.format(token),
        'Content-type': 'application/json',
        'Accept': 'application/json',
        'dp-meta-option': 'none',
    }
    self.timeout = timeout
    self._page = 1
    self.page_api_requests = page_api_requests
    self.maximum_page_depth = maximum_page_depth

  @property
  def datetime_override(self) -> Optional[Text]:
    return self._datetime_override

  @datetime_override.setter
  def datetime_override(self, value: Optional[Text]):
    """Set datetime_override attribute.

    Args:
      value: str in a format parseable by '%Y-%m-%d %H:%M:%S' or None.
        For example: "2001-01-01 20:00:00".

    Raises:
      ValueError if value can't be parsed as expected.
    """
    if value is None or _validate_timestamp_string(value):
      self._datetime_override = value
    else:
      raise ValueError(
          'time_override must be of format "YYYY-MM-DD HH:MM:SS". Got: %s' %
          value)

  def get_current_time(self) -> datetime.datetime:
    """Gets the current time or instance's time override.

    If overridden, return could be in the past or future. This function wraps
    around datetime.now(), allowing for a time override to set as an
    instance attribute.

    Returns:
      datetime.datetime in UTC timezone.
    """
    if self.datetime_override is not None:
      now = dateutil.parser.parse(self.datetime_override)
      now.astimezone(dateutil.tz.UTC)
    else:
      now = datetime.datetime.now(tz=dateutil.tz.UTC)
    return now

  def query_api(
      self,
      resource: Text,
      query: Query,
      method: Text = 'POST',
      ) -> List[Dict[Text, Any]]:
    """Sends HTTP request to Deputy API.

    Args:
      resource: The API resource name, like 'resource/Roster/QUERY'.
        See: https://www.deputy.com/api-doc/API/Resource_Calls
      query: Query to transform to Dictionary and send in request.
      method: The HTTP method to use to with fetch_url, like 'GET'.

    Returns:
      List of dictionaries from the API, where each dictionary is a single
      record of the resource type queried.

    Raises:
      TypeError or json.decoder.JSONDecodeError if failed to parse the JSON
        response from the Deputy service.
      ConnectionError If there is an error with the underlying connection.
    """
    url = self._build_request_url(resource)
    body = json.dumps(query.to_dict()).encode('utf-8')

    response = self.http.request(method, url, headers=self._headers, body=body,
                                 timeout=self.timeout)
    try:
      result = json.loads(response.data.decode('utf-8'))
    except (TypeError, json.decoder.JSONDecodeError):
      logging.exception('Querying %s failed, result is not a valid Json.',
                        resource)
      raise

    if len(result) >= 500 and self.page_api_requests:
      if self._page < self.maximum_page_depth:
        self._page += 1
        logging.info('Requesting page %s of query to %s', self._page, resource)
        query.start += 500
        result.extend(self.query_api(resource, query, method))
        return result
    # Reset page count before next API call.
    self._page = 1
    return result

  def _build_request_url(
      self,
      resource_name: Text,
      ) -> Text:
    """Builds request url from given resource name.

    Args:
      resource_name: API resource. Ex: 'resource/Roster/QUERY'.

    Returns:
      URL to call for request.
    """
    url = urllib.parse.urlparse(
        urllib.parse.urljoin(self.endpoint, resource_name))
    return url.geturl()

  def get_trainings(
      self,
      query: Optional[Query] = None,
      ) -> Trainings:
    """Gets trainings from the Deputy API.

    Args:
      query: Query to use against the 'resource/TrainingRecord/QUERY'
        endpoint in the Deputy API. If None, defaults to:
        Query(join=['EmployeeObject', 'ModuleObject'])

    Returns:
      list of Training objects with corresponding values.
    """
    if query is None:
      query = Query(join=['EmployeeObject', 'ModuleObject'])

    api_response = self.query_api('resource/TrainingRecord/QUERY', query)

    return [Training.from_api_response(training_dict.get('ModuleObject', {}))
            for training_dict in api_response]

  def get_stress_profiles(
      self,
      query: Optional[Query] = None,
      ) -> StressProfiles:
    """Gets stress profiles from Deputy API.

    Args:
      query: Query to use for querying 'resource/StressProfile/QUERY'.
        If None, defaults to: Query().

    Returns:
      list of StressProfile objects with corresponding values.
    """
    if query is None:
      query = Query()

    api_response = self.query_api('resource/StressProfile/QUERY', query)

    return [StressProfile.from_api_response(profile_dict)
            for profile_dict in api_response]

  def get_employees(
      self,
      employee_query: Optional[Query] = None,
      training_query: Optional[Query] = None,
      include_trainings: bool = True,
      ) -> Employees:
    """Gets employees from Deputy API.

    Common recipes:
    - Get employee by Id:
      employee_query = Query(
        select={'active': {'field': 'Active', 'type': 'eq', 'data': True},
                'id': {'field': 'Id', 'type': 'eq', 'data': $ID}},
        join=['ContactObject', 'StressProfileObject', 'CompanyObject'])

    - Get employee by email:
      employee_query = Query(
        select={'active': {'field': 'Active', 'type': 'eq', 'data': True}},
        join_select={'email': {'field': 'Email1', 'type': 'eq',
                               'data': $EMAIL, 'join': 'ContactObject'}},
        join=['ContactObject', 'StressProfileObject', 'CompanyObject'])

      (No, that is not a typo, query 'Email1'. See:
       https://www.deputy.com/api-doc/Resources/Contact)

    Args:
      employee_query: Query to use for querying
        'resource/Employee/QUERY'. If None, defaults to:
        Query(
          join=['ContactObject', 'StressProfileObject', 'CompanyObject'],
          select={'active_true': {'field': 'Active', 'type': 'eq',
                                  'data': True}}).
      training_query: Query to use for querying
        'resource/TrainingRecord/QUERY'. Only used if 'include_trainings=True'.
        If None, defaults to:
        Query(join=['EmployeeObject', 'ModuleObject'])
      include_trainings: Whether or not to also query API for trainings,
        and join those to the employee object. If trainings are not required,
        this can be set to False for a cheaper request.

    Returns:
      list of Employee objects with corresponding values.
    """
    if employee_query is None:
      employee_query = Query(
          join=['ContactObject', 'StressProfileObject', 'CompanyObject'],
          select={'active_true': {'field': 'Active', 'type': 'eq',
                                  'data': True}})
    if training_query is None:
      training_query = Query(join=['EmployeeObject', 'ModuleObject'])

    employees = []
    employee_api_response = self.query_api(
        'resource/Employee/QUERY', employee_query)

    trainings = {}
    if include_trainings:
      # construct a data structure to easily map employees to their trainings.
      # { employee_id: [training1, training2] }
      training_api_response = self.query_api(
          'resource/TrainingRecord/QUERY', training_query)
      for training_dict in training_api_response:
        trainings.setdefault(
            training_dict['Employee'], []).append(training_dict)

    for employee in employee_api_response:
      employees.append(Employee.from_api_response(
          employee, trainings.get(employee['Id'], [])))

    return employees

  def get_shifts(
      self,
      shift_query: Optional[Query] = None,
      employee_query: Optional[Query] = None,
      include_employee_trainings: bool = True,
      ) -> Shifts:
    """Gets shifts from Deputy API.

    Common recipes:
    - Get currently active shifts (also default behavior). Seconds is typically
      obtained via self.get_current_time():
      shift_query = Query(
        select={'Employee_0': {'field': 'Employee', 'type': 'ne', 'data': 0},
                'StartTime': {'field': 'StartTime', 'type': 'le',
                              'data': client.get_current_time().timestamp()},
                'EndTime': {'field': 'EndTime', 'type': 'ge',
                            'data': client.get_current_time().timestamp()}},
        join=['EmployeeObject'])

      This can be expanded upon to gather shifts at any arbitrary time by
      replacing the value for 'data'.

    Args:
      shift_query: Query to use for querying the shifts within a queue.
        This is used to query against the 'resource/Roster/QUERY' endpoint. If
        None, defaults to querying currently active shifts:
        Query(select={'Employee_0': {'field': 'Employee', 'type': 'ne',
                                     'data': 0},
                      'StartTime': {'field': 'StartTime', 'type': 'le',
                                    'data':
                                      self.get_current_time().timestamp()},
                      'EndTime': {'field': 'EndTime', 'type': 'ge',
                                  'data': self.get_current_time().timestamp()}},
              join=['EmployeeObject'])
      employee_query: Query to use for querying employees within the
        shifts. This is used to query against the 'resource/Employee/QUERY'
        endpoint. It will always have a select key of 'id_in' - a query
        submitted with this as a key in the 'select' dictionary will have that
        key overridden. If None, defaults to querying all employees found in
        shifts, with joins needed for all metadata:
        Query(
          select={'active_true': {'field': 'Active', 'type': 'eq',
                                  'data': True},
                  'id_in': {'field': 'Id', 'type': 'in',
                            'data': [list of ids in found shifts]}},
          join=['ContactObject', 'StressProfileObject', 'CompanyObject'])
      include_employee_trainings: Whether or not to include trainings in
        employee responses. Setting to False makes one fewer call to the API 
        [per 500 employees] and doesn't fill in training data.

    Returns:
      Shift objects with corresponding values.
    """
    if shift_query is None:
      shift_query = Query(
          select={
              'Employee_0': {'field': 'Employee', 'type': 'ne', 'data': 0},
              'StartTime': {
                  'field': 'StartTime', 'type': 'le',
                  'data': self.get_current_time().timestamp()},
              'EndTime': {
                  'field': 'EndTime', 'type': 'ge',
                  'data': self.get_current_time().timestamp()}},
          join=['EmployeeObject'])

    if employee_query is None:
      employee_query = Query(
          select={'active_true': {'field': 'Active', 'type': 'eq',
                                  'data': True}},
          join=['ContactObject', 'StressProfileObject', 'CompanyObject'])

    shift_api_response = self.query_api(
        'resource/Roster/QUERY', shift_query)

    employee_ids = [shift_dict['Employee'] for shift_dict in shift_api_response]

    employee_query.select.update(
        {'id_in': {'field': 'Id', 'type': 'in', 'data': employee_ids}})

    employees = self.get_employees(
        employee_query=employee_query,
        include_trainings=include_employee_trainings)

    employee_ids = {employee.user_id: employee for employee in employees}

    shifts = []
    for shift_dict in shift_api_response:
      shifts.append(Shift.from_api_response(
          shift_dict, employee_ids[shift_dict['Employee']]))

    return shifts

  def get_queues(
      self,
      queue_query: Optional[Query] = None,
      shift_query: Optional[Query] = None,
      employee_query: Optional[Query] = None,
      include_employee_trainings: bool = True,
      ) -> Queues:
    """Gets queues from Deputy API.

    Common recipes:
    - Get queue by ID:
    queue_query = Query(
      select={'Employee_0': {'field': 'Employee', 'type': 'ne', 'data': 0},
              'Queue_id': {'field': 'Id', 'type': 'eq', 'data': $ID}}
      assoc=['TrainingModule'])

    - Get queue by name:
    queue_query = Query(
      select={'Employee_0': {'field': 'Employee', 'type': 'ne', 'data': 0},
              'Name': {'field': 'OperationalUnitName', 'type': 'eq',
                       'data': $NAME}},
      assoc=['TrainingModule'])

    Args:
      queue_query: Query to use for querying
        'resource/OperationalUnit/QUERY'. If None, defaults to:
        Query(select={'id_0': {'field': 'Id', 'type': 'ne', 'data': 0}},
              join=['CompanyObject'],
              assoc=['TrainingModule']).
      shift_query: Query to use for querying the shifts within a queue.
        This is the 'resource/Roster/QUERY' endpoint. It will always have a
        select key of 'id_in' - a query submitted with this as a key in the
        'select' dictionary will have that key overridden. If None, defaults
        to querying currently active shifts inside found queues:
        Query(select={'Employee_0': {'field': 'Employee', 'type': 'ne',
                                     'data': 0},
                      'published': {'field': 'Published', 'type': 'eq',
                                    'data': True},
                      'StartTime': {'field': 'StartTime', 'type': 'le',
                                    'data': self.get_current_time()},
                      'EndTime': {'field': 'EndTime', 'type': 'ge',
                                  'data': self.get_current_time()},
                      'id_in': {'field': 'OperationalUnit', 'type': 'in',
                                   'data': [Ids found in queue query]}},
              join=['EmployeeObject'])
      employee_query: Query to use for querying employees within the
        shifts. This is the 'resource/Employee/QUERY' endpoint. It will always
        have a select key of 'id_in' - a query submitted with this as a key in
        the 'select' dictionary will have that key overridden. If None,
        defaults to querying all employees in found shifts, with joins needed
        for all metadata:
        Query(
          select={'active_true': {'field': 'Active', 'type': 'eq',
                                  'data': True},
                  'id_in': {'field': 'Id', 'type': 'in',
                            'data': [list of ids in found shifts]}},
          join=['ContactObject', 'StressProfileObject', 'CompanyObject'])
      include_employee_trainings: Whether or not to include trainings in
        employee responses. Setting to False makes one fewer call to the API
        [per 500 employees] and doesn't fill in training data.

    Returns:
      Queue objects with corresponding values.
    """
    if queue_query is None:
      queue_query = Query(
          select={'id_0': {'field': 'Id', 'type': 'ne', 'data': 0}},
          join=['CompanyObject'],
          assoc=['TrainingModule'])

    if shift_query is None:
      shift_query = Query(
          select={
              'Employee_0': {'field': 'Employee', 'type': 'ne', 'data': 0},
              'published': {'field': 'Published', 'type': 'eq', 'data': True},
              'StartTime': {
                  'field': 'StartTime', 'type': 'le',
                  'data': self.get_current_time().timestamp()},
              'EndTime': {
                  'field': 'EndTime', 'type': 'ge',
                  'data': self.get_current_time().timestamp()}},
          join=['EmployeeObject'])

    if employee_query is None:
      employee_query = Query(
          select={'active_true': {'field': 'Active', 'type': 'eq',
                                  'data': True}},
          join=['ContactObject', 'StressProfileObject', 'CompanyObject'])

    queue_api_response = self.query_api(
        'resource/OperationalUnit/QUERY', queue_query)

    queue_ids = [queue_dict['Id'] for queue_dict in queue_api_response]

    shift_query.select.update(
        {'id_in': {'field': 'OperationalUnit', 'type': 'in', 'data': queue_ids}}
        )

    shifts = self.get_shifts(
        shift_query, employee_query, include_employee_trainings)

    queue_shift_map = {}
    for shift in shifts:
      queue_shift_map.setdefault(shift.queue_id, []).append(shift)

    queues = []
    for queue_dict in queue_api_response:
      queues.append(Queue.from_api_response(
          queue_dict, queue_shift_map.get(queue_dict['Id'])))

    return queues

  def get_leaves(
      self,
      leaves_query: Optional[Query] = None,
      include_employee_trainings: bool = True,
      ) -> Leaves:
    """Gets leaves from Deputy API.

    Common recipes:
    - Get leaves for an employee by id:
      Query(
        select={
            'start': {
                'field': 'Start', 'type': 'ge',
                'data': self.get_current_time().timestamp()},
            'end': {
                'field': 'End', 'type': 'le',
                'data': self.get_current_time().timestamp()}
            'employee_id': {
                'field': 'Employee', 'type': 'eq', 'data': $ID}},
        join=['EmployeeObject'])

    Args:
      leaves_query: Query to use for querying 'resource/Leave/QUERY'.
        If None, defaults to:
        Query(
          select={
              'start': {
                  'field': 'Start', 'type': 'ge',
                  'data': self.get_current_time().timestamp()},
              'end': {
                  'field': 'End', 'type': 'le',
                  'data': self.get_current_time().timestamp()}},
          join=['EmployeeObject'])
      include_employee_trainings: bool, Whether or not to include trainings for
        employees attached to a leave. If False, trainings are excluded and one
        less call is made to the API [per 500 employees].

    Returns:
      Leave objects with corresponding values.
    """
    if leaves_query is None:
      leaves_query = Query(
          select={
              'start': {
                  'field': 'Start', 'type': 'le',
                  'data': self.get_current_time().timestamp()},
              'end': {
                  'field': 'End', 'type': 'ge',
                  'data': self.get_current_time().timestamp()}},
          join=['EmployeeObject'])

    leave_api_response = self.query_api(
        'resource/Leave/QUERY', leaves_query)

    employee_ids = [leave_dict['Employee'] for leave_dict in leave_api_response]
    employee_query = Query(
        select={'id_in': {'field': 'Id', 'type': 'in', 'data': employee_ids}},
        join=['ContactObject', 'StressProfileObject', 'CompanyObject'])

    employees = self.get_employees(
        employee_query=employee_query,
        include_trainings=include_employee_trainings)

    employee_to_id = {employee.user_id: employee for employee in employees}

    leaves = []
    for leave_dict in leave_api_response:
      leave = Leave.from_api_response(
          leave_dict, employee_to_id[leave_dict['Employee']])
      leaves.append(leave)

    return leaves


def main(argv) -> None:
  del argv  # Unused.
  print('Use of Deputy as a binary is solely for manual debugging.')
  print('To test, add changes to main() and remove them before submitting.')

if __name__ == '__main__':
  app.run(main)

