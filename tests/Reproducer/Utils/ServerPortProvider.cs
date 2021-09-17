﻿#region License
// Copyright 2021 AppMotor Framework (https://github.com/skrysmanski/AppMotor)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#endregion

using JetBrains.Annotations;

namespace Reproducer.Utils
{
    /// <summary>
    /// Provides each test with its own port. This is necessary because tests
    /// run in parallel.
    /// </summary>
    public static class ServerPortProvider
    {
        private static readonly object s_lock = new();

        private static int s_nextPort = 1234;

        /// <summary>
        /// Provides a port to be used for testing.
        /// </summary>
        [MustUseReturnValue]
        public static int GetNextTestPort()
        {
            lock (s_lock)
            {
                int port = s_nextPort;
                s_nextPort++;
                return port;
            }
        }
    }
}
