// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
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

#include "algorithm_description.h"

#include <algorithm>
#include <fstream>
#include <regex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include <fmt/format.h>
#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>

namespace encrypto::motion {

AlgorithmDescription AlgorithmDescription::FromBristol(const std::string& path) {
  std::ifstream file_stream(path);
  return FromBristol(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromBristol(std::string&& path) {
  std::ifstream file_stream(std::move(path));
  return FromBristol(file_stream);
}

//
// Bristol format
// 49 65            *** total # of gates, total # of wires
// 8 8 8            *** # input wires parent a, # input wires parent b, # of output wires
//                  *** empty line
// *** below, only gate-related infos:
// *** # of input shares (bundled wires, i.e., XOR has 2 inputs, INV 1, and MUX 3),
// *** # of outputs,
// *** input wire ids (1--many)
// *** output wire ids (usually 1)
// *** gate type
// 2 1 0 8 57 XOR
// 2 1 1 9 16 XOR   ***
// 2 1 0 8 17 AND   ***
// ...
//

AlgorithmDescription AlgorithmDescription::FromBristol(std::ifstream& stream) {
  AlgorithmDescription algorithm_description;
  assert(stream.is_open());
  assert(stream.good());
  stream >> algorithm_description.number_of_gates >> algorithm_description.number_of_wires;
  algorithm_description.constant_wires.assign(algorithm_description.number_of_wires,
                                              std::nullopt);

  std::vector<std::string> line_vector;
  std::string line;
  std::getline(stream, line);  // skip \n at the end of the first line
  // second line
  {
    std::string second_line;
    std::getline(stream, second_line);
    std::stringstream ss(second_line);
    while (std::getline(ss, line, ' ')) {
      line_vector.emplace_back(std::move(line));
      line.clear();
    }
    algorithm_description.number_of_input_wires_parent_a = std::stoull(line_vector.at(0));
    if (line_vector.size() == 2) {
      algorithm_description.number_of_output_wires = std::stoull(line_vector.at(1));
    } else if (line_vector.size() == 3) {
      algorithm_description.number_of_input_wires_parent_b = std::stoull(line_vector.at(1));
      algorithm_description.number_of_output_wires = std::stoull(line_vector.at(2));
    } else {
      throw std::runtime_error(
          std::string("Unexpected number of values: " + std::to_string(line_vector.size()) + "\n"));
    }
    line.clear();
    line_vector.clear();
  }

  std::getline(stream, line);
  assert(line.empty());

  // read line
  const auto reverse_chunks = [](std::vector<long long>& ids, std::size_t chunk) {
    if (chunk == 0 || ids.empty() || ids.size() % chunk != 0) return;
    for (std::size_t offset = 0; offset < ids.size(); offset += chunk) {
      std::reverse(ids.begin() + offset, ids.begin() + offset + chunk);
    }
  };

  while (std::getline(stream, line)) {
    std::stringstream ss(line);
    // split line
    while (std::getline(ss, line, ' ')) {
      boost::algorithm::trim(line);
      if (!line.empty()) {
        line_vector.emplace_back(std::move(line));
      }
    }

    if (line_vector.empty()) continue;
    std::string type = line_vector.at(line_vector.size() - 1);
    boost::algorithm::trim(type);
    PrimitiveOperation primitive_operation;
    if (type == std::string("XOR") || type == std::string("AND") || type == std::string("ADD") ||
        type == std::string("MUL") || type == std::string("OR")) {
      assert(line_vector.size() == 6);
      if (type == std::string("XOR"))
        primitive_operation.type = PrimitiveOperationType::kXor;
      else if (type == std::string("AND"))
        primitive_operation.type = PrimitiveOperationType::kAnd;
      else if (type == std::string("ADD"))
        primitive_operation.type = PrimitiveOperationType::kAdd;
      else if (type == std::string("MUL"))
        primitive_operation.type = PrimitiveOperationType::kMul;
      else if (type == std::string("OR"))
        primitive_operation.type = PrimitiveOperationType::kOr;
      primitive_operation.parent_a = std::stoull(line_vector.at(2));
      primitive_operation.parent_b = std::stoull(line_vector.at(3));
      primitive_operation.output_wire = std::stoull(line_vector.at(4));
    } else if (type == std::string("MUX")) {
      assert(line_vector.size() == 7);
      primitive_operation.type = PrimitiveOperationType::kMux;
      primitive_operation.parent_a = std::stoull(line_vector.at(2));
      primitive_operation.parent_b = std::stoull(line_vector.at(3));
      primitive_operation.selection_bit = std::stoull(line_vector.at(4));
      primitive_operation.output_wire = std::stoull(line_vector.at(5));
    } else if (type == std::string("INV")) {
      assert(line_vector.size() == 5);
      primitive_operation.type = PrimitiveOperationType::kInv;
      primitive_operation.parent_a = std::stoull(line_vector.at(2));
      primitive_operation.output_wire = std::stoull(line_vector.at(3));
    } else {
      throw std::runtime_error("Unknown operation type: " + line_vector.at(line_vector.size() - 1) +
                               "\n");
    }
    algorithm_description.gates.emplace_back(primitive_operation);
    line.clear();
    line_vector.clear();
  }
  // Default output ordering: last number_of_output_wires wires.
  for (std::size_t i = algorithm_description.number_of_wires -
                          algorithm_description.number_of_output_wires;
       i < algorithm_description.number_of_wires; ++i) {
    algorithm_description.output_wire_indices.push_back(i);
  }

  return algorithm_description;
}

AlgorithmDescription AlgorithmDescription::FromBristolFashion(const std::string& path) {
  std::ifstream file_stream(path);
  return FromBristolFashion(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromBristolFashion(std::string&& path) {
  std::ifstream file_stream(std::move(path));
  return FromBristolFashion(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromBristolFashion(std::ifstream& stream) {
  AlgorithmDescription algorithm_description;
  assert(stream.is_open());
  assert(stream.good());

  constexpr std::size_t kGateEncodingLineNumber = 4;
  const static std::regex kLineTwoNumbersRegex("^\\s*(\\d+)\\s+(\\d+)\\s*$");
  const static std::regex kLineThreeNumbersRegex("^\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*$");
  const static std::regex kLineGateRegex(
      "^\\s*(1|2)\\s+(1)\\s+(\\d+)\\s+(\\d+\\s+)?(\\d+)\\s+(XOR|AND|INV)\\s*$");
  const static std::regex kLineWhitespaceRegex("^\\s*$");

  std::string line;
  std::smatch match;

  // first line
  std::getline(stream, line);
  if (!std::regex_match(line, match, kLineTwoNumbersRegex)) {
    throw std::runtime_error("Cannot parse Bristol Fashion file at line 1");
  }
  algorithm_description.number_of_gates = boost::lexical_cast<std::size_t>(match[1]);
  algorithm_description.number_of_wires = boost::lexical_cast<std::size_t>(match[2]);

  // second line
  std::getline(stream, line);
  if (std::regex_match(line, match, kLineTwoNumbersRegex)) {
    auto n = boost::lexical_cast<std::size_t>(match[1]);
    if (n != 1) {
      throw std::runtime_error("Malformed Bristol Fashion format at line 2");
    }
    algorithm_description.number_of_input_wires_parent_a =
        boost::lexical_cast<std::size_t>(match[2]);
  } else if (std::regex_match(line, match, kLineThreeNumbersRegex)) {
    auto n = boost::lexical_cast<std::size_t>(match[1]);
    if (n != 2) {
      throw std::runtime_error("Malformed Bristol Fashion format at line 2");
    }
    algorithm_description.number_of_input_wires_parent_a =
        boost::lexical_cast<std::size_t>(match[2]);
    algorithm_description.number_of_input_wires_parent_b =
        boost::lexical_cast<std::size_t>(match[3]);
  } else {
    throw std::runtime_error(
        "Cannot parse Bristol Fashion file at line 2 (maybe unsupported number of input values)");
  }

  // third line
  std::getline(stream, line);
  if (std::regex_match(line, match, kLineTwoNumbersRegex)) {
    auto n = boost::lexical_cast<std::size_t>(match[1]);
    if (n != 1) {
      throw std::runtime_error("Malformed Bristol Fashion format at line 3");
    }
    algorithm_description.number_of_output_wires = boost::lexical_cast<std::size_t>(match[2]);
  } else {
    throw std::runtime_error(
        "Cannot parse Bristol Fashion file at line 3 (maybe unsupported number of output values)");
  }

  // consume empty line
  std::getline(stream, line);
  assert(line.empty());

  std::size_t line_number = kGateEncodingLineNumber;

  // read gates
  while (std::getline(stream, line)) {
    ++line_number;
    if (line.empty() || std::regex_match(line, kLineWhitespaceRegex)) {
      continue;
    }

    if (!std::regex_match(line, match, kLineGateRegex)) {
      throw std::runtime_error(
          fmt::format("Cannot parse Bristol Fashion file at line {}", line_number));
    }

    using namespace std::string_literals;

    auto number_of_inputs = boost::lexical_cast<std::size_t>(match[1]);
    const auto& operation = match[6];
    PrimitiveOperation primitive_operation;

    if (operation == "XOR"s) {
      if (number_of_inputs != 2) {
        throw std::runtime_error(fmt::format(
            "Cannot parse Bristol Fashion file at line {}: invalid number of inputs", line_number));
      }
      primitive_operation.type = PrimitiveOperationType::kXor;
    } else if (operation == "AND"s) {
      if (number_of_inputs != 2) {
        throw std::runtime_error(fmt::format(
            "Cannot parse Bristol Fashion file at line {}: invalid number of inputs", line_number));
      }
      primitive_operation.type = PrimitiveOperationType::kAnd;
    } else if (operation == "INV"s) {
      if (number_of_inputs != 1) {
        throw std::runtime_error(fmt::format(
            "Cannot parse Bristol Fashion file at line {}: invalid number of inputs", line_number));
      }
      primitive_operation.type = PrimitiveOperationType::kInv;
    }
    primitive_operation.output_wire = boost::lexical_cast<std::size_t>(match[5]);
    primitive_operation.parent_a = boost::lexical_cast<std::size_t>(match[3]);
    if (number_of_inputs == 2) {
      std::string input_b = match[4];
      boost::trim(input_b);
      primitive_operation.parent_b = boost::lexical_cast<std::size_t>(input_b);
    }
    algorithm_description.gates.emplace_back(std::move(primitive_operation));
  }

  algorithm_description.constant_wires.assign(algorithm_description.number_of_wires,
                                              std::nullopt);
  // Default output ordering: last number_of_output_wires wires.
  for (std::size_t i = algorithm_description.number_of_wires -
                          algorithm_description.number_of_output_wires;
       i < algorithm_description.number_of_wires; ++i) {
    algorithm_description.output_wire_indices.push_back(i);
  }

  return algorithm_description;
}

AlgorithmDescription AlgorithmDescription::FromAby(const std::string& path) {
  std::ifstream file_stream(path);
  return FromAby(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromAby(std::string&& path) {
  std::ifstream file_stream(std::move(path));
  return FromAby(file_stream);
}

AlgorithmDescription AlgorithmDescription::FromAby(std::ifstream& stream) {
  AlgorithmDescription algorithm_description;
  assert(stream.is_open());
  assert(stream.good());

  std::string line;
  std::size_t server_inputs = 0, client_inputs = 0;
  std::size_t next_wire_id = 0;
  std::unordered_map<long long, std::size_t> wire_map;
  std::unordered_map<long long, bool> const_map;
  std::unordered_set<long long> defined_wires;

  const auto map_wire = [&](long long external_id) -> std::size_t {
    auto it = wire_map.find(external_id);
    if (it != wire_map.end()) return it->second;
    auto id = next_wire_id++;
    wire_map.emplace(external_id, id);
    return id;
  };

  const auto define_wire = [&](long long external_id) -> std::size_t {
    auto [_, inserted] = defined_wires.emplace(external_id);
    if (!inserted) {
      throw std::runtime_error(fmt::format("Wire {} is redefined in ABY file", external_id));
    }
    return map_wire(external_id);
  };

  const auto require_defined_wire = [&](long long external_id,
                                        const char* context) -> std::size_t {
    if (defined_wires.find(external_id) == defined_wires.end()) {
      throw std::runtime_error(fmt::format(
          "Wire {} is used before definition in ABY file ({})", external_id, context));
    }
    auto it = wire_map.find(external_id);
    assert(it != wire_map.end());
    return it->second;
  };

  const auto read_wire_ids = [](std::stringstream& ss) {
    std::vector<long long> wire_ids;
    long long wire_id = 0;
    while (ss >> wire_id) {
      wire_ids.push_back(wire_id);
    }
    return wire_ids;
  };

  while (std::getline(stream, line)) {
    boost::algorithm::trim(line);
    if (line.empty()) {
      continue;
    }

    const char identifier = line.front();
    if (identifier == '#') {
      continue;
    }

    std::stringstream ss(line);
    ss >> std::ws;
    char tag;
    ss >> tag;
    if (!ss || tag != identifier) {
      throw std::runtime_error("Malformed line in ABY file");
    }

    switch (identifier) {
      case 'C': {
        auto wire_ids = read_wire_ids(ss);
        client_inputs += wire_ids.size();
        for (auto id : wire_ids) {
          define_wire(id);
        }
        break;
      }
      case 'S': {
        auto wire_ids = read_wire_ids(ss);
        server_inputs += wire_ids.size();
        for (auto id : wire_ids) {
          define_wire(id);
        }
        break;
      }
      case 'O': {
        auto wire_ids = read_wire_ids(ss);
        algorithm_description.number_of_output_wires += wire_ids.size();
        for (auto id : wire_ids) {
          algorithm_description.output_wire_indices.push_back(require_defined_wire(id, "output"));
        }
        break;
      }
      case '0':
      case '1': {
        long long wire_id = 0;
        if (!(ss >> wire_id)) {
          throw std::runtime_error("Malformed constant declaration in ABY file");
        }
        define_wire(wire_id);
        const_map[wire_id] = (identifier == '1');
        break;
      }
      case 'A':
      case 'X':
      case 'V': {
        long long in0_ext = 0, in1_ext = 0, out_ext = 0;
        if (!(ss >> in0_ext >> in1_ext >> out_ext)) {
          throw std::runtime_error("Malformed binary gate definition in ABY file");
        }

        PrimitiveOperation gate;
        gate.parent_a = require_defined_wire(in0_ext, "binary gate input A");
        gate.parent_b = require_defined_wire(in1_ext, "binary gate input B");
        gate.output_wire = define_wire(out_ext);
        if (identifier == 'A') {
          gate.type = PrimitiveOperationType::kAnd;
        } else if (identifier == 'X') {
          gate.type = PrimitiveOperationType::kXor;
        } else {
          gate.type = PrimitiveOperationType::kOr;
        }
        algorithm_description.gates.emplace_back(std::move(gate));
        break;
      }
      case 'M': {
        long long in0_ext = 0, in1_ext = 0, sel_ext = 0, out_ext = 0;
        if (!(ss >> in0_ext >> in1_ext >> sel_ext >> out_ext)) {
          throw std::runtime_error("Malformed MUX gate definition in ABY file");
        }

        PrimitiveOperation gate;
        gate.type = PrimitiveOperationType::kMux;
        gate.parent_a = require_defined_wire(in0_ext, "MUX input A");
        gate.parent_b = require_defined_wire(in1_ext, "MUX input B");
        gate.selection_bit = require_defined_wire(sel_ext, "MUX selection");
        gate.output_wire = define_wire(out_ext);
        algorithm_description.gates.emplace_back(std::move(gate));
        break;
      }
      case 'I': {
        long long in_ext = 0, out_ext = 0;
        if (!(ss >> in_ext >> out_ext)) {
          throw std::runtime_error("Malformed INV gate definition in ABY file");
        }

        PrimitiveOperation gate;
        gate.type = PrimitiveOperationType::kInv;
        gate.parent_a = require_defined_wire(in_ext, "INV input");
        gate.output_wire = define_wire(out_ext);
        algorithm_description.gates.emplace_back(std::move(gate));
        break;
      }
      default:
        break;
    }
  }

  algorithm_description.constant_wires.assign(next_wire_id, std::nullopt);
  for (const auto& [ext, value] : const_map) {
    auto it = wire_map.find(ext);
    assert(it != wire_map.end());
    algorithm_description.constant_wires.at(it->second) = value;
  }

  if (server_inputs > 0 && client_inputs > 0) {
    algorithm_description.number_of_input_wires_parent_a = server_inputs;
    algorithm_description.number_of_input_wires_parent_b = client_inputs;
  } else {
    algorithm_description.number_of_input_wires_parent_a = server_inputs + client_inputs;
    algorithm_description.number_of_input_wires_parent_b = std::nullopt;
  }

  algorithm_description.number_of_gates = algorithm_description.gates.size();
  algorithm_description.number_of_wires = next_wire_id;

  return algorithm_description;
}

}  // namespace encrypto::motion





