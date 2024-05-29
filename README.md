# Paycek

This is an official package for the [Paycek crypto payment processor](https://paycek.io). The documentation provided in code explains only minor implementation details.

For in depth information about endpoints, fields and more, read our [API Documentation](https://paycek.io/api/docs).

## Quick Start

### Installation

Install package from nuget.

```shell
dotnet add package Paycek --version 1.1.1
```

### Initialization

Under account settings you’ll find your API key and secret. Initialize a paycek instance.

```
Paycek paycek = new Paycek("<apiKey>", "<apiSecret>");
```

### Usage

#### Get payment

```
dynamic response = paycek.GetPayment("<paymentCode>");
```

#### Open payment

```
Dictionary<string, object> optionalFields = new Dictionary<string, object>();
optionalFields.Add("location_id", "<locationId>");

dynamic test = paycek.OpenPayment("<profileCode>", "<dstAmount>", optionalFields);
```
