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

using System;
using System.Net.Http;

namespace AppMotor.Core.Net.Http
{
    /// <summary>
    /// Creates instances of <see cref="HttpClient"/>. Use this class if you need something other than
    /// the default settings.
    /// </summary>
    public static class HttpClientFactory
    {
        public static HttpClient CreateHttpClient()
        {
            var handler = new HttpClientHandler();
            try
            {
                return new HttpClient(handler);
            }
            catch (Exception)
            {
                handler.Dispose();
                throw;
            }
        }
    }
}
