// MIT License
//
// Copyright (c) 2019 Lennart Braun
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "run_time_statistics.h"
#include <fmt/format.h>
#include <algorithm>
#include <cmath>
#include <sstream>
#include <string>

namespace encrypto::motion {

static double ToMilliseconds(const RunTimeStatistics::Duration& duration) {
  std::chrono::duration<double, std::milli> milliseconds = duration;
  return milliseconds.count();
}

const RunTimeStatistics::TimePointPair& RunTimeStatistics::Get(StatisticsId id) const {
  return data.at(static_cast<std::size_t>(id));
}

RunTimeStatistics::Duration RunTimeStatistics::GetDuration(StatisticsId id) const {
  const auto idx = static_cast<std::size_t>(id);
  return data.at(idx).second - data.at(idx).first + accumulated_durations.at(idx);
}

void RunTimeStatistics::Reset() {
  data = {};
  accumulated_durations = {};
}

template <typename C>
typename C::value_type At(const C& container, RunTimeStatistics::StatisticsId id) {
  return container.at(static_cast<std::size_t>(id));
}

std::string RunTimeStatistics::PrintHumanReadable() const {
  std::array<double, std::tuple_size_v<decltype(data)>> milliseconds;
  for (std::size_t i = 0; i < milliseconds.size(); ++i) {
    milliseconds.at(i) = ToMilliseconds(GetDuration(static_cast<StatisticsId>(i)));
  }
  auto max = *std::max_element(milliseconds.cbegin(), milliseconds.cend());
  auto width = max > 0.0 ? static_cast<std::size_t>(std::ceil(std::log10(max))) + 4 : 5;

  std::stringstream ss;
  ss << fmt::format("MT Presetup         {:{}.3f} ms\n",
                    At(milliseconds, StatisticsId::kMtPresetup), width)
     << fmt::format("MT Setup            {:{}.3f} ms\n", At(milliseconds, StatisticsId::kMtSetup),
                    width)
     << fmt::format("SP Presetup         {:{}.3f} ms\n",
                    At(milliseconds, StatisticsId::kSpPresetup), width)
     << fmt::format("SP Setup            {:{}.3f} ms\n", At(milliseconds, StatisticsId::kSpSetup),
                    width)
     << fmt::format("SB Presetup         {:{}.3f} ms\n",
                    At(milliseconds, StatisticsId::kSbPresetup), width)
     << fmt::format("SB Setup            {:{}.3f} ms\n", At(milliseconds, StatisticsId::kSbSetup),
                    width)
     << fmt::format("Base OTs            {:{}.3f} ms\n", At(milliseconds, StatisticsId::kBaseOts),
                    width)
     << fmt::format("OT Extension Setup  {:{}.3f} ms\n",
                    At(milliseconds, StatisticsId::kOtExtensionSetup), width)
     << fmt::format("KK13 OT Extension Setup  {:{}.3f} ms\n",
                    At(milliseconds, StatisticsId::kKK13OtExtensionSetup), width)
     << fmt::format("-------------------------\n")
     << fmt::format("Preprocessing Total {:{}.3f} ms\n",
                    At(milliseconds, StatisticsId::kPreprocessing), width)
     << fmt::format("Gates Setup         {:{}.3f} ms\n",
                    At(milliseconds, StatisticsId::kGatesSetup), width)
     << fmt::format("Gates Online        {:{}.3f} ms\n",
                    At(milliseconds, StatisticsId::kGatesOnline), width)
     << fmt::format("Synchronization     {:{}.3f} ms\n",
                    At(milliseconds, StatisticsId::kSynchronize), width)
     << fmt::format("-------------------------\n")
     << fmt::format("Circuit Evaluation  {:{}.3f} ms\n", At(milliseconds, StatisticsId::kEvaluate),
                    width);
  return ss.str();
}

}  // namespace encrypto::motion
