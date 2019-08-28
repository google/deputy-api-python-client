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

"""Tests for deputy.py."""

import datetime
import json
import unittest
import unittest.mock

from absl.testing import absltest
from absl.testing import flagsaver

import dateutil.parser
import deputy

import parameterized
import urllib3

ONCALL_TRAINING = deputy.Training(
    name='Oncall',
    comment='Training to join an oncall queue.')

ONCALL_TRAINING_API_RESPONSE = {
    'Title': 'Oncall',
    'Comment': 'Training to join an oncall queue.'}

TRAINING_RECORD_API_RESPONSE = {
    'Id': 100,
    'Employee': 2,
    'ModuleObject': ONCALL_TRAINING_API_RESPONSE}

DAILY_STRESS_PROFILE = deputy.StressProfile(
    profile_id=1,
    profile_name='Daily',
    max_hours_per_shift=8,
    max_hours_per_week=40,
    max_days_per_week=5,
    max_hours_per_day=8,
    gap_hours_between_shifts=24,
    creator_id=1,
    created=dateutil.parser.parse('2019-01-01 11:00:00'),
    modified=dateutil.parser.parse('2019-01-02 11:00:00'))

STRESS_PROFILE_API_RESPONSE = {
    'Id': 1,
    'Name': 'Daily',
    'MaxHoursPerShift': 8,
    'MaxHoursPerPeriod': 40,
    'MaxDaysPerPeriod': 5,
    'MaxHoursPerDay': 8,
    'GapHoursBetweenShifts': 24,
    'Creator': 1,
    'Created': '2019-01-01 11:00:00',
    'Modified': '2019-01-02 11:00:00'}

JOHNNYCACHE_EMPLOYEE = deputy.Employee(
    user_id=2,
    display_name='Johnny Cache',
    first_name='Johnny',
    last_name='Cache',
    email_address='johnnycache@domain.com',
    start_date=dateutil.parser.parse('2019-02-03 11:00:00'),
    termination_date=None,
    active=True,
    creator_id=1,
    username='johnnycache',
    location='FULLSUM_PRISON',
    stress_profile=DAILY_STRESS_PROFILE,
    trainings=[ONCALL_TRAINING])

EMPLOYEE_API_RESPONSE = {
    'Id': 2,
    'DisplayName': 'Johnny Cache',
    'FirstName': 'Johnny',
    'LastName': 'Cache',
    'StartDate': '2019-02-03 11:00:00',
    'Active': True,
    'Creator': 1,
    'ContactObject': {
        'Email': 'johnnycache@domain.com'},
    'CompanyObject': {
        'CompanyName': 'FULLSUM_PRISON'},
    'StressProfileObject': STRESS_PROFILE_API_RESPONSE}

ONCALL_ROSTER_API_RESPONSE = {
    'OperationalUnit': 2,
    'Employee': 2,
    'EmployeeObject': {
        'Id': 2},
    'OperationalUnitObject': {
        'OperationalUnit': 2,
        'OperationalUnitName': 'Tool Oncall'},
    'StartTime': 1549825200,  # 2019-02-10 11:00:00.
    'EndTime': 1549846800,  # 2019-02-10 17:00:00.
    'Comment': 'Taking shift for a peer.'}

ONCALL_JOHNNYCACHE_SHIFT = deputy.Shift(
    queue_id=2,
    start_time=datetime.datetime.fromtimestamp(1549825200, tz=dateutil.tz.UTC),
    end_time=datetime.datetime.fromtimestamp(1549846800, tz=dateutil.tz.UTC),
    description='Taking shift for a peer.',
    employee=JOHNNYCACHE_EMPLOYEE)

ONCALL_QUEUE_API_RESPONSE = {
    'Id': 2,
    'CompanyObject': {
        'CompanyName': 'West Coast'},
    'OperationalUnitName': 'Tool Oncall',
    'TrainingModule': [ONCALL_TRAINING_API_RESPONSE]}

ONCALL_QUEUE = deputy.Queue(
    queue_id=2,
    queue_name='Tool Oncall',
    location='West Coast',
    trainings=[ONCALL_TRAINING],
    shifts=[ONCALL_JOHNNYCACHE_SHIFT])

JOHNNYCACHE_LEAVE_API_RESPONSE = {
    'Comment': 'Some comment.',
    'Start': 1549825200,  # 2019-02-10 11:00:00.
    'End': 1549846800,  # 2019-02-10 17:00:00.
    'Employee': 2}

JOHNNYCACHE_LEAVE = deputy.Leave(
    comment='Some comment.',
    start_time=datetime.datetime.fromtimestamp(1549825200, tz=dateutil.tz.UTC),
    end_time=datetime.datetime.fromtimestamp(1549846800, tz=dateutil.tz.UTC),
    employee=JOHNNYCACHE_EMPLOYEE)


def _make_http_response(body):
  return urllib3.HTTPResponse(body=bytes(json.dumps(body), 'utf-8'))


class DeputyTest(unittest.TestCase):

  def setUp(self):
    super(DeputyTest, self).setUp()
    self.mock_http = unittest.mock.Mock()
    self.deputy_instance = deputy.Deputy(
        'https://example.au.deputy.com/api/v1/',
        self.mock_http,
        '12345',
        None,
        10000)

  @parameterized.parameterized.expand([
      ('Success', '2018-11-19 19:30:00', True),
      ('Failure', 'Wow, what a datestring', False),
  ])
  def testValidateTimestampString(self, _, test_value, expected_result):
    """Checks that the flag validator succeeds and fails as needed."""
    self.assertEqual(
        deputy._validate_timestamp_string(test_value),
        expected_result)

  def testDeputyFromFlags(self):
    """Test that deputy.Deputy gets instantiated from flags successfully."""
    with flagsaver.flagsaver(
        uri_regional_endpoint='https://{}.au.deputy.com/api/v1/',
        endpoint_hostname='example',
        deputy_auth_token='12345',
        current_datetime_override='2019-01-01 11:00:05',
        deputy_request_timeout=10000):
      deputy_instance = deputy.Deputy.from_flags()
    self.assertEqual(
        deputy_instance.endpoint, 'https://example.au.deputy.com/api/v1/')
    self.assertEqual(deputy_instance.datetime_override, '2019-01-01 11:00:05')
    self.assertEqual(deputy_instance.timeout, 10000)

  def testDeputyInit_EndpointRaisesValueError(self):
    """Tests that an error is raised when provided value is a bad format."""
    with self.assertRaises(ValueError):
      deputy.Deputy(
          'wow, a completely unformatted endpoint',
          self.mock_http,
          '12345')

  def testDatetimeOverride_RaisesValueError(self):
    """Deputy.datetime_override raises ValueError when set to a bad format."""
    with self.assertRaises(ValueError):
      self.deputy_instance.datetime_override = 'unexpected string format.'

  def testDatetimeOverride(self):
    """Test that datetime_override can successfully be set."""
    self.deputy_instance.datetime_override = '2019-01-01 11:00:55'
    self.assertEqual(self.deputy_instance.datetime_override,
                     '2019-01-01 11:00:55')

  @parameterized.parameterized.expand([
      ('InvalidSelect', {'select': {'employee_0': {'field': 'Id'}}}),
      ('InvalidJoinSelect', {'join_select': {'employee_0': {'field': 'Id'}}}),
      ('f1SetInKeys', {'select': {'f1': {'field': 'Id', 'type': 'ne',
                                         'data': 0}}}),
  ])
  def testQuery_RaisesValueError_(self, _, test_kwargs):
    """Tests that Query object raises ValueError for attributes."""
    with self.assertRaises(ValueError):
      deputy.Query(**test_kwargs)

  def testQueryAPI(self):
    """Tests that query_api returns expected body."""
    self.mock_http.request.return_value = urllib3.HTTPResponse(
        body=b'{"expected": "body"}')
    actual_response = self.deputy_instance.query_api(
        'resource/Roster/QUERY', deputy.Query())
    self.assertEqual(actual_response, {'expected': 'body'})

  @parameterized.parameterized.expand([
      ('3PageRequest', 3, 1001),
      ('1PageRequest', 1, 500),
  ])
  def testQueryAPI_PagesRequest(self, _, page_depth, result_length):
    """Tests that multiple requests are made when 500 records in response."""
    long_response = []
    for _ in range(0, 500):
      long_response.append({'dummy': 'data'})

    self.mock_http.request.side_effect = [
        urllib3.HTTPResponse(body=bytes(json.dumps(long_response), 'utf-8')),
        urllib3.HTTPResponse(body=bytes(json.dumps(long_response), 'utf-8')),
        urllib3.HTTPResponse(
            body=bytes(json.dumps({'dummy': 'data'}), 'utf-8'))]

    deputy_instance = deputy.Deputy(
        'https://example.au.deputy.com/api/v1/',
        self.mock_http,
        '12345',
        None,
        10000,
        True,
        page_depth)

    result = deputy_instance.query_api(
        'resource/Roster/QUERY', deputy.Query())
    self.assertEqual(len(result), result_length)

  def testBuildRequestUrl(self):
    """Tests that _build_request_url succeeds."""
    url = self.deputy_instance._build_request_url('resource/Roster/QUERY')
    self.assertEqual(
        url, 'https://example.au.deputy.com/api/v1/resource/Roster/QUERY')

  def testGetCurrentTime_ReturnsOverride(self):
    """Tests that deputy instance returns overridden time."""
    self.deputy_instance.datetime_override = '2019-01-02 11:00:00'
    actual_time = self.deputy_instance.get_current_time()
    expected_time = dateutil.parser.parse('2019-01-02 11:00:00')
    self.assertEqual(actual_time, expected_time)

  @parameterized.parameterized.expand([
      ('Training', deputy.Training, [ONCALL_TRAINING_API_RESPONSE],
       ONCALL_TRAINING),
      ('StressProfile', deputy.StressProfile, [STRESS_PROFILE_API_RESPONSE],
       DAILY_STRESS_PROFILE),
      ('Employee', deputy.Employee,
       [EMPLOYEE_API_RESPONSE, [TRAINING_RECORD_API_RESPONSE]],
       JOHNNYCACHE_EMPLOYEE),
      ('Shift', deputy.Shift,
       [ONCALL_ROSTER_API_RESPONSE, JOHNNYCACHE_EMPLOYEE],
       ONCALL_JOHNNYCACHE_SHIFT),
      ('Queue', deputy.Queue,
       [ONCALL_QUEUE_API_RESPONSE, [ONCALL_JOHNNYCACHE_SHIFT]],
       ONCALL_QUEUE),
      ('Leave', deputy.Leave,
       [JOHNNYCACHE_LEAVE_API_RESPONSE, JOHNNYCACHE_EMPLOYEE],
       JOHNNYCACHE_LEAVE),
  ])
  def testFromAPIResponse_(
      self, _, class_name, constructor_args, expected_object):
    """Tests that API response objects instantiate with expected values."""
    actual_object = class_name.from_api_response(*constructor_args)

    self.assertEqual(actual_object, expected_object)

  @parameterized.parameterized.expand([
      ('Trainings', [_make_http_response([TRAINING_RECORD_API_RESPONSE])],
       'get_trainings',
       [ONCALL_TRAINING]),
      ('StressProfiles', [_make_http_response([STRESS_PROFILE_API_RESPONSE])],
       'get_stress_profiles',
       [DAILY_STRESS_PROFILE]),
      ('Employees',
       [_make_http_response([EMPLOYEE_API_RESPONSE]),
        _make_http_response([TRAINING_RECORD_API_RESPONSE])],
       'get_employees',
       [JOHNNYCACHE_EMPLOYEE]),
      ('Shifts',
       [_make_http_response([ONCALL_ROSTER_API_RESPONSE]),
        _make_http_response([EMPLOYEE_API_RESPONSE]),
        _make_http_response([TRAINING_RECORD_API_RESPONSE])],
       'get_shifts',
       [ONCALL_JOHNNYCACHE_SHIFT]),
      ('Queues',
       [_make_http_response([ONCALL_QUEUE_API_RESPONSE]),
        _make_http_response([ONCALL_ROSTER_API_RESPONSE]),
        _make_http_response([EMPLOYEE_API_RESPONSE]),
        _make_http_response([TRAINING_RECORD_API_RESPONSE])],
       'get_queues',
       [ONCALL_QUEUE]),
      ('Leaves',
       [_make_http_response([JOHNNYCACHE_LEAVE_API_RESPONSE]),
        _make_http_response([EMPLOYEE_API_RESPONSE]),
        _make_http_response([TRAINING_RECORD_API_RESPONSE])],
       'get_leaves',
       [JOHNNYCACHE_LEAVE]),
  ])
  def testGet_(self, _, http_responses, method_name, expected_result):
    """Tests that getter methods return expected result."""
    self.mock_http.request.side_effect = http_responses

    test_method = getattr(self.deputy_instance, method_name)
    actual_result = test_method()

    self.assertEqual(actual_result, expected_result)


if __name__ == '__main__':
  absltest.main()

