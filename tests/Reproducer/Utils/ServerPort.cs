#region License
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

using System;

using JetBrains.Annotations;

namespace AppMotor.Core.Net
{
    public sealed class ServerPort
    {
        /// <summary>
        /// From where to accept connections.
        /// </summary>
        [PublicAPI]
        public SocketListenAddresses ListenAddress { get; }

        /// <summary>
        /// The port to use.
        /// </summary>
        [PublicAPI]
        public int Port { get; }

        public ServerPort(SocketListenAddresses listenAddress, int port)
        {
            if (port < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(port));
            }

            this.ListenAddress = listenAddress;
            this.Port = port;
        }
    }
}
