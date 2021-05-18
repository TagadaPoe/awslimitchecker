"""
awslimitchecker/services/cloudfront.py

The latest version of this package is available at:
<https://github.com/jantman/awslimitchecker>

################################################################################
Copyright 2015-2018 Jason Antman <jason@jasonantman.com>

    This file is part of awslimitchecker, also known as awslimitchecker.

    awslimitchecker is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    awslimitchecker is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with awslimitchecker.  If not, see <http://www.gnu.org/licenses/>.

The Copyright and Authors attributions contained herein may not be removed or
otherwise altered, except to add the Author attribution of a contributor to
this work. (Additional Terms pursuant to Section 7b of the AGPL v3)
################################################################################
While not legally required, I sincerely request that anyone who finds
bugs please submit them at <https://github.com/jantman/awslimitchecker> or
to me via email, and that you send any contributions or improvements
either as a pull request on GitHub, or to me via email.
################################################################################

AUTHORS:
Jason Antman <jason@jasonantman.com> <http://www.jasonantman.com>
################################################################################
"""

import abc  # noqa
import logging

from .base import _AwsService
from ..limit import AwsLimit

logger = logging.getLogger(__name__)


class _CloudfrontService(_AwsService):

    service_name = "CloudFront"
    api_name = "cloudfront"  # AWS API name to connect to (boto3.client)
    quotas_service_code = "cloudfront"

    def find_usage(self):
        """
        Determine the current usage for each limit of this service,
        and update corresponding Limit via
        :py:meth:`~.AwsLimit._add_current_usage`.
        """
        logger.debug("Checking usage for service %s", self.service_name)
        self.connect()
        for lim in self.limits.values():
            lim._reset_usage()
        # TODO: update your usage here, i.e.:
        """
        usage = self.conn.method_to_get_usage()
        # or, if it needs to be paginated,  something like:
        # remebering to 'from ..utils import paginate_dict'
        usage = paginate_dict(
            self.conn.method_to_get_usage,
            alc_marker_path=['NextToken'],
            alc_data_path=['ResourceListName'],
            alc_marker_param='NextToken'
        )
        u_id = (resource id from AWS)
        self.limits['Number of u']._add_current_usage(u, aws_type='U', id=u_id)
        """
        self._have_usage = True
        logger.debug("Done checking usage.")

    def get_limits(self):
        """
        Return all known limits for this service, as a dict of their names
        to :py:class:`~.AwsLimit` objects.

        :returns: dict of limit names to :py:class:`~.AwsLimit` objects
        :rtype: dict
        """
        if self.limits != {}:
            return self.limits
        limits = {}
        # L-24B04930	Web distributions per AWS account   200
        limits["Web distributions per AWS account"] = AwsLimit(
            "Distributions per AWS account",
            self,
            200,
            self.warning_threshold,
            self.critical_threshold,
            limit_type="AWS::CloudFront::Distribution",
            quotas_name="Web distributions per AWS account",
        )
        # L-F432D044	Cache behaviors per distribution    25
        limits["Cache behaviors per distribution"] = AwsLimit(
            "Cache behaviors per distribution",
            self,
            25,
            self.warning_threshold,
            self.critical_threshold,
            limit_type=None,
        )
        # L-9EBD26CA	Public keys in a single key group   5
        limits["Public keys in a single key group"] = AwsLimit(
            "Public keys in a single key group",
            self,
            5,
            self.warning_threshold,
            self.critical_threshold,
            limit_type="AWS::CloudFront::PublicKey",
        )
        # L-E7E9ACEB	Key groups associated with a single distribution   4
        limits["Key groups associated with a single distribution"] = AwsLimit(
            "Key groups associated with a single distribution",
            self,
            4,
            self.warning_threshold,
            self.critical_threshold,
            limit_type="AWS::CloudFront::KeyGroup",
        )
        # L-D64DA6E2    Key groups per AWS account    10
        limits["Key groups per AWS account"] = AwsLimit(
            "Key groups per AWS account",
            self,
            10,
            self.warning_threshold,
            self.critical_threshold,
            limit_type="AWS::CloudFront::KeyGroup",
        )
        # L-C19110C4	Distributions associated with a single key group    100
        limits["Distributions associated with a single key group"] = AwsLimit(
            "Distributions associated with a single key group",
            self,
            100,
            self.warning_threshold,
            self.critical_threshold,
            limit_type="AWS::CloudFront::KeyGroup",
        )

        self.limits = limits
        return limits

    def _update_limits_from_api(self):
        """
        Call the service's API action to retrieve limit/quota information, and
        update AwsLimit objects in ``self.limits`` with this information.
        """
        # TODO: if the service has an API that can retrieve current limit information
        # i.e. ``DescribeAccountAttributes``, call that action here and update each
        # relevant AwsLimit object (in ``self.limits``) via its ``._set_api_limit()`` method.
        # ELSE if the service has no API call for this, remove this method.
        raise NotImplementedException()

    def required_iam_permissions(self):
        """
        Return a list of IAM Actions required for this Service to function
        properly. All Actions will be shown with an Effect of "Allow"
        and a Resource of "*".

        :returns: list of IAM Action strings
        :rtype: list
        """
        # TODO: update this to be all IAM permissions required for find_usage() to work
        return [
            "Cloudfront:SomeAction",
        ]
